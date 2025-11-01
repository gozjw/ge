package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/term"
)

// go build -ldflags "-s -w" -a -trimpath

const (
	chunkSize = 4 * 1024 * 1024 // 4MiB
	saltSize  = 16
	nonceSize = chacha20poly1305.NonceSizeX

	geFilePrefix = "ge_"
	geFileSuffix = ".ge"
)

var programPath string

func main() {
	programPath, _ = filepath.Abs(os.Args[0])
	if len(os.Args) > 1 {
		runWithArg()
		return
	}
	runNoArg()
}

func runNoArg() {
	var op string
	enList, deList, rnList := sortsFile(getDirFile("."))
	for {
		op = ""
		fmt.Print("-----文件加解密-----\n1.加密文件\n2.解密文件\n3.还原文件名\n4.清除屏幕\nq.退出\n请选择：")
		fmt.Scanln(&op)
		switch op {
		case "1":
			enList = selectAeDeFile(enList, "加密")
			enAndDeFile(enList, []GeFile{})
		case "2":
			deList = selectAeDeFile(deList, "解密")
			enAndDeFile([]GeFile{}, deList)
		case "3":
			rnFile(selectRnFile(rnList))
		case "4":
			clearScreen()
			goto flesh
		case "q":
			return
		}
		fmt.Println()
	flesh:

		enList, deList, rnList = sortsFile(getDirFile("."))
	}
}

func selectRnFile(rnList [][2]string) (target [][2]string) {
	if len(rnList) == 0 {
		fmt.Println("\n无需要还原名称的文件！")
		return
	}

	fmt.Println("\n重命名列表：")
	for i, f := range rnList {
		fmt.Println(i+1, f[0], "->", f[1])
	}
	fmt.Println(len(rnList)+1, "全部")

	fmt.Print("\n选择重命名文件的序号，多个文件以/分隔，如1/2/3\n请选择：")
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
		if index == len(rnList) {
			target = rnList
			return
		}
		if index < 0 || index >= len(rnList) {
			continue
		}
		if _, ok := indexMap[index]; ok {
			continue
		}
		target = append(target, rnList[index])
		indexMap[index] = struct{}{}
	}
	return
}

func rnFile(rnList [][2]string) {
	if len(rnList) > 0 {
		fmt.Println()
	}
	for _, f := range rnList {
		err := os.Rename(f[0], f[1])
		if err != nil {
			fmt.Println("重命名", f[0], "->", f[1], err)
		} else {
			fmt.Println("重命名", f[0], "->", f[1], "成功")
		}
	}
}

func clearScreen() {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("clear")
	case "windows":
		cmd = exec.Command("cmd", "/c", "cls")
	default:
		return
	}
	cmd.Stdout = os.Stdout
	cmd.Run()
}

func selectAeDeFile(src []GeFile, desc string) (target []GeFile) {
	if len(src) == 0 {
		return
	}

	var opSign = "（已" + desc + "）"
	fmt.Printf("\n%s列表：\n", desc)
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
			abs, err := filepath.Abs(arg)
			if err != nil || abs == programPath {
				continue
			}
			allFileList = append(allFileList, abs)
		}
	}

	enList, deList, rnList := sortsFile(allFileList)

	if len(rnList) > 0 && len(enList) == 0 && len(deList) == 0 {
		rnFile(rnList)
		return
	}

	enAndDeFile(enList, deList)
}

type GeFile struct {
	Path   string
	OpSign bool
}

func sortsFile(allFileList []string) (enList, deList []GeFile, rnList [][2]string) {
	allFileMap := make(map[string]struct{})
	list := make([]string, 0)
	for _, fp := range allFileList {
		if _, ok := allFileMap[fp]; ok {
			continue
		}
		list = append(list, fp)
		allFileMap[fp] = struct{}{}
	}

	for _, abs := range list {
		fileName := filepath.Base(abs)

		if strings.HasPrefix(fileName, geFilePrefix) {
			rnList = append(rnList, [2]string{abs,
				filepath.Join(filepath.Dir(abs),
					strings.TrimPrefix(fileName, geFilePrefix))})
			continue
		}

		if strings.HasSuffix(fileName, geFileSuffix) {
			_, ok := allFileMap[getGeFilePrefixName(abs)]
			if ok && len(os.Args) > 1 {
				continue
			}
			deList = append(deList, GeFile{Path: abs, OpSign: ok})
		} else {
			_, ok := allFileMap[abs+geFileSuffix]
			if ok && len(os.Args) > 1 {
				continue
			}
			enList = append(enList, GeFile{Path: abs, OpSign: ok})
		}
	}
	return
}

func enAndDeFile(enList []GeFile, deList []GeFile) {
	var enLen = len(enList)
	var deLen = len(deList)
	if enLen == 0 && deLen == 0 {
		fmt.Println("\n未选择文件!")
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

func getDirFile(dir string) (absPaths []string) {
	filepath.Walk(dir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			absPath, err := filepath.Abs(path)
			if err != nil {
				return err
			}
			if absPath == programPath {
				return nil
			}
			absPaths = append(absPaths, absPath)
			return nil
		})
	return
}

func getGeFilePrefixName(p string) string {
	name := filepath.Base(p)
	name = geFilePrefix + strings.TrimSuffix(name, geFileSuffix)
	return filepath.Join(filepath.Dir(p), name)
}

func deriveKey(password []byte, salt []byte) []byte {
	return argon2.IDKey(password, salt, 3, 64*1024, 4, 32)
}

func enFile(password []byte, srcPath string) error {
	salt := make([]byte, saltSize)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return err
	}

	key := deriveKey(password, salt)

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}

	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(srcPath + geFileSuffix)
	if err != nil {
		return err
	}
	defer dst.Close()

	dst.Write(salt)
	dst.Write(nonce)
	var csBuf [8]byte

	buf := make([]byte, chunkSize)
	var chunkIndex uint64

	for {
		n, err := io.ReadFull(src, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return err
		}
		if n == 0 {
			return nil
		}

		binary.BigEndian.PutUint64(nonce[nonceSize-8:], chunkIndex)

		ct := aead.Seal(nil, nonce, buf[:n], nil)

		binary.BigEndian.PutUint64(csBuf[:], uint64(len(ct)))
		if _, err := dst.Write(csBuf[:]); err != nil {
			return err
		}
		if _, err := dst.Write(ct); err != nil {
			return err
		}

		chunkIndex++
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return nil
		}
	}
}

func deFile(password []byte, srcPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(src, salt); err != nil {
		return err
	}

	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(src, nonce); err != nil {
		return err
	}

	var csBuf [8]byte

	key := deriveKey(password, salt)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return err
	}

	dst, err := os.Create(getGeFilePrefixName(srcPath))
	if err != nil {
		return err
	}
	defer dst.Close()

	var chunkIndex uint64
	for {
		if _, err := io.ReadFull(src, csBuf[:]); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		ctLen := int(binary.BigEndian.Uint64(csBuf[:]))
		ct := make([]byte, ctLen)
		if _, err := io.ReadFull(src, ct); err != nil {
			return err
		}

		binary.BigEndian.PutUint64(nonce[nonceSize-8:], chunkIndex)

		pt, err := aead.Open(nil, nonce, ct, nil)
		if err != nil {
			return errors.New("密码错误")
		}
		if _, err := dst.Write(pt); err != nil {
			return err
		}
		chunkIndex++
	}
}
