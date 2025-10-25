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
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

// go build -ldflags "-s -w" -a -trimpath

var geFilePrefix = "ge_"
var geFileSuffix = ".ge"

var programPath string

func main() {
	programPath = os.Args[0]
	if len(os.Args) > 1 {
		runWithArg()
		return
	}
	runNoArg()
}

func runNoArg() {
	var allFileList []string
	var enList, deList []GeFile
	var op string
	for {
		op = ""
		allFileList = make([]string, 0)
		for _, fp := range getDirFile(".") {
			absPath, err := filepath.Abs(fp)
			if err != nil {
				continue
			}
			if absPath == programPath {
				continue
			}
			allFileList = append(allFileList, absPath)
		}

		enList, deList = getFileAbsPath(allFileList)

		fmt.Print("文件加解密\n1.加密\n2.解密\nq.退出\n请选择：")
		fmt.Scanln(&op)
		fmt.Println()
		switch op {
		case "1":
			enList = selectFile(enList, "加密")
			deList = make([]GeFile, 0)
		case "2":
			deList = selectFile(deList, "解密")
			enList = make([]GeFile, 0)
		case "q":
			return
		default:
			goto flesh
		}

		enAndDeFile(enList, deList)
		fmt.Println()

	flesh:
	}
}

func selectFile(src []GeFile, desc string) (target []GeFile) {
	if len(src) == 0 {
		return
	}

	var opSign = "（已" + desc + "）"
	fmt.Printf("%s列表：\n", desc)
	for i, v := range src {
		if v.OpSign {
			fmt.Println(i+1, v.Path, opSign)
		} else {
			fmt.Println(i+1, v.Path)
		}
	}
	fmt.Println(len(src)+1, "全部")

	fmt.Printf("\n选择需要%s文件的序号，多个文件以/分隔，如1/2/3\n请选择：", desc)
	var indexMap = make(map[int]struct{})
	var input string
	fmt.Scanln(&input)
	for _, v := range strings.Split(input, "/") {
		v = strings.TrimSpace(v)
		index, err := strconv.Atoi(v)
		if err != nil {
			continue
		}
		index--
		if index == len(src) {
			return src
		}
		if index < 0 || index >= len(src) {
			continue
		}
		if _, ok := indexMap[index]; ok {
			continue
		}
		target = append(target, src[index])
		indexMap[index] = struct{}{}
	}
	if len(target) == 0 {
		fmt.Println()
	}
	return
}

func runWithArg() {
	allFileList := make([]string, 0)
	for _, arg := range os.Args[1:] {
		fileInfo, err := os.Stat(arg)
		if err != nil {
			continue
		}
		if fileInfo.IsDir() {
			allFileList = append(allFileList, getDirFile(arg)...)
		} else {
			allFileList = append(allFileList, arg)
		}
	}

	enList, deList := getFileAbsPath(allFileList)

	enAndDeFile(enList, deList)
}

type GeFile struct {
	Path   string
	OpSign bool
}

func getFileAbsPath(allFileList []string) (enList []GeFile, deList []GeFile) {
	allFileMap := make(map[string]struct{})
	list := make([]string, 0)
	for _, fp := range allFileList {
		absPath, err := filepath.Abs(fp)
		if err != nil {
			continue
		}
		if absPath == programPath {
			continue
		}
		if _, ok := allFileMap[absPath]; ok {
			continue
		}
		list = append(list, absPath)
		allFileMap[absPath] = struct{}{}
	}

	for _, fileAbs := range list {
		fileName := filepath.Base(fileAbs)

		if strings.HasPrefix(fileName, geFilePrefix) {
			continue
		}

		if strings.HasSuffix(fileName, geFileSuffix) {
			_, ok := allFileMap[getGeFilePrefixName(fileAbs)]
			if ok && len(os.Args) > 1 {
				continue
			}
			deList = append(deList, GeFile{Path: fileAbs, OpSign: ok})
		} else {
			_, ok := allFileMap[fileAbs+geFileSuffix]
			if ok && len(os.Args) > 1 {
				continue
			}
			enList = append(enList, GeFile{Path: fileAbs, OpSign: ok})
		}
	}
	return
}

func enAndDeFile(enList []GeFile, deList []GeFile) {
	var enLen = len(enList)
	var deLen = len(deList)
	if enLen == 0 && deLen == 0 {
		fmt.Println("无操作文件!")
		return
	}

	fmt.Print("\n请设置密码：")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println("\n密码错误", err)
		return
	}
	if len(password) == 0 {
		fmt.Println("\n密码不能为空!")
		return
	}
	if len(password) >= 32 {
		fmt.Println("\n密码过长!")
		return
	}

	fmt.Println()
	if enLen > 0 {
		fmt.Print("请确认密码：")
		confirmPassword, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			fmt.Println("\n输入确认密码错误", err)
			return
		}
		if !bytes.Equal(password, confirmPassword) {
			fmt.Println("\n确认密码错误!")
			return
		}

		fmt.Println()
		fmt.Printf("\n加密列表(%d):\n", enLen)
		for i, v := range enList {
			fmt.Println(i+1, v.Path)
		}
	}

	if deLen > 0 {
		fmt.Printf("\n解密列表(%d):\n", deLen)
		for i, v := range deList {
			fmt.Println(i+1, v.Path)
		}
	}

	var confirm string
	fmt.Print("\n确认操作(y-确认/n-取消):")
	fmt.Scanln(&confirm)
	if confirm != "y" {
		return
	}

	var start time.Time
	if enLen > 0 {
		fmt.Println()
	}
	for i, v := range enList {
		fmt.Printf("加密(%d/%d)：%s ", i+1, enLen, v.Path)
		start = time.Now()
		err := enFile(password, v.Path)
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
		fmt.Printf("解密(%d/%d)：%s ", i+1, deLen, v.Path)
		start = time.Now()
		err := deFile(password, v.Path)
		if err != nil {
			fmt.Printf(" 错误:%s\n", err.Error())
		} else {
			fmt.Printf(" 用时:%fs\n", time.Since(start).Seconds())
		}
	}
}

func getDirFile(dir string) (paths []string) {
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

	geFile, err := os.OpenFile(srcFilePath+geFileSuffix,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
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

	srcFile, err := os.OpenFile(getGeFilePrefixName(geFilePath),
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	defer srcFile.Close()

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
