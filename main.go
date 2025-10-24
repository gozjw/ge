package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

// go build -ldflags "-s -w" -a -trimpath

var geFilePrefix = "ge_"
var geFileSuffix = ".ge"

func main() {
	if len(os.Args) <= 1 {
		fmt.Println("参数错误!")
		return
	}

	programPath := os.Args[0]

	filePathList := make([]string, 0)
	for _, arg := range os.Args[1:] {
		fileInfo, err := os.Stat(arg)
		if err != nil {
			continue
		}
		if fileInfo.IsDir() {
			filePathList = append(filePathList, getAllFilePath(arg)...)
		} else {
			filePathList = append(filePathList, arg)
		}
	}

	allFilePathMap := make(map[string]struct{})
	for _, fp := range filePathList {
		absPath, err := filepath.Abs(fp)
		if err != nil {
			continue
		}
		if absPath == programPath {
			continue
		}
		allFilePathMap[absPath] = struct{}{}
	}

	var isEn bool
	var enList, deList []string
	for absPath := range allFilePathMap {
		isEn = true

		fileName := filepath.Base(absPath)
		if strings.HasPrefix(fileName, geFilePrefix) {
			continue
		}

		if strings.HasSuffix(fileName, geFileSuffix) {
			isEn = false
		}

		if isEn {
			if _, ok := allFilePathMap[absPath+geFileSuffix]; ok {
				continue
			}
			enList = append(enList, absPath)
		} else {
			if _, ok := allFilePathMap[getGeFilePrefixName(absPath)]; ok {
				continue
			}
			deList = append(deList, absPath)
		}
	}

	var enLen = len(enList)
	var deLen = len(deList)
	if enLen == 0 && deLen == 0 {
		fmt.Println("无操作文件!")
		return
	}

	var confirmPassword []byte
	fmt.Print("请输入密码：")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println("\n密码错误", err)
		return
	}
	if len(password) == 0 {
		fmt.Println("密码不能为空!")
		return
	}
	if len(password) >= 32 {
		fmt.Println("密码过长!")
		return
	}

	fmt.Println()
	if enLen > 0 {
		fmt.Print("请确认密码：")
		confirmPassword, err = term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			fmt.Println("\n确认密码错误", err)
			return
		}
		fmt.Println()
		if !bytes.Equal(password, confirmPassword) {
			fmt.Println("确认密码错误!")
			return
		}
		fmt.Printf("\n加密列表(%d):\n", enLen)
		for i, v := range enList {
			fmt.Println(i+1, v)
		}
	}

	if deLen > 0 {
		fmt.Printf("\n解密列表(%d):\n", deLen)
		for i, v := range deList {
			fmt.Println(i+1, v)
		}
	}

	var confirm string
	fmt.Print("\n确认操作(y/n):")
	fmt.Scanln(&confirm)
	if confirm != "y" {
		return
	}

	var start time.Time
	if enLen > 0 {
		fmt.Println()
	}
	for i, v := range enList {
		fmt.Printf("加密(%d/%d)：%s ", i+1, enLen, v)
		start = time.Now()
		err = enFile(password, v)
		if err != nil {
			fmt.Printf(" 错误:%s\n", err.Error())
		} else {
			fmt.Printf(" 用时:%fs\n", time.Since(start).Seconds())
		}
	}

	if deLen > 0 {
		fmt.Println()
	}
	for i, v := range deList {
		fmt.Printf("解密(%d/%d)：%s ", i+1, deLen, v)
		start = time.Now()
		err = deFile(password, v)
		if err != nil {
			fmt.Printf(" 错误:%s\n", err.Error())
		} else {
			fmt.Printf(" 用时:%fs\n", time.Since(start).Seconds())
		}
	}
}

func getAllFilePath(dir string) (paths []string) {
	paths = make([]string, 0)
	filepath.Walk(dir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			paths = append(paths, path)
			return nil
		})
	return
}

func enFile(key []byte, srcFilePath string) error {
	bcryptKey, err := bcrypt.GenerateFromPassword(key, 0)
	if err != nil {
		return err
	}

	pkcsKey := PKCS7Padding(key, 16)
	block, err := aes.NewCipher(pkcsKey)
	if err != nil {
		return err
	}
	blockSize := block.BlockSize()
	iv := make([]byte, blockSize)
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return err
	}
	mode := cipher.NewCBCEncrypter(block, iv)

	srcFile, err := os.Open(srcFilePath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	geFile, err := os.OpenFile(srcFilePath+geFileSuffix, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer geFile.Close()

	// 校验码长度 1位
	_, err = geFile.Write([]byte{byte(len(bcryptKey))})
	if err != nil {
		return err
	}
	// 校验码
	_, err = geFile.Write(bcryptKey)
	if err != nil {
		return err
	}
	// iv长度 1位
	_, err = geFile.Write([]byte{byte(len(iv))})
	if err != nil {
		return err
	}
	// iv
	_, err = geFile.Write(iv)
	if err != nil {
		return err
	}

	// 16M
	bufSize := blockSize * 1024 * 1000

	// 数据块长度 8位
	_, err = geFile.Write(IntToBytes(bufSize))
	if err != nil {
		return err
	}

	data := make([]byte, bufSize)
	for {
		count, err := srcFile.Read(data)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		if count < bufSize {
			data = PKCS7Padding(data[:count], blockSize)
		}
		mode.CryptBlocks(data, data)
		_, err = geFile.Write(data)
		if err != nil {
			return err
		}
	}
}

func getGeFilePrefixName(p string) string {
	name := filepath.Base(p)
	name = geFilePrefix + strings.TrimSuffix(name, geFileSuffix)
	return filepath.Join(filepath.Dir(p), name)
}

func deFile(key []byte, geFilePath string) error {
	geFile, err := os.Open(geFilePath)
	if err != nil {
		return err
	}
	defer geFile.Close()

	geFileInfo, err := os.Stat(geFilePath)
	if err != nil {
		return err
	}
	geFileSize := int(geFileInfo.Size())

	// 检验码长度
	keyLB := make([]byte, 1)
	_, err = geFile.Read(keyLB)
	if err != nil {
		return err
	}
	keyLI := int(keyLB[0])
	// 检验码
	bcryptKey := make([]byte, keyLI)
	_, err = geFile.Read(bcryptKey)
	if err != nil {
		return err
	}
	// 校验密码
	err = bcrypt.CompareHashAndPassword(bcryptKey, key)
	if err != nil {
		return errors.New("密码错误")
	}
	// iv长度
	ivLB := make([]byte, 1)
	_, err = geFile.Read(ivLB)
	if err != nil {
		return err
	}
	ivLI := int(ivLB[0])
	// iv
	iv := make([]byte, ivLI)
	_, err = geFile.Read(iv)
	if err != nil {
		return err
	}
	// 数据块长度 8位
	bufL := make([]byte, 8)
	_, err = geFile.Read(bufL)
	if err != nil {
		return err
	}
	bufSize := BytesToInt(bufL)
	geFileSize = geFileSize - 1 - keyLI - 1 - ivLI - 8

	totalBlock := geFileSize / bufSize
	if geFileSize%bufSize > 0 {
		totalBlock += 1
	}

	pkcsKey := PKCS7Padding(key, 16)
	block, err := aes.NewCipher(pkcsKey)
	if err != nil {
		return err
	}
	mode := cipher.NewCBCDecrypter(block, iv)

	srcFile, err := os.OpenFile(getGeFilePrefixName(geFilePath), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer geFile.Close()

	data := make([]byte, bufSize)
	for {
		count, err := geFile.Read(data)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		totalBlock -= 1
		mode.CryptBlocks(data, data)
		if totalBlock == 0 {
			data = PKCS7UnPadding(data[:count])
		}
		_, err = srcFile.Write(data)
		if err != nil {
			return err
		}
	}
}

func IntToBytes(i int) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(i))
	return buf
}

func BytesToInt(buf []byte) int {
	return int(binary.BigEndian.Uint64(buf))
}

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
