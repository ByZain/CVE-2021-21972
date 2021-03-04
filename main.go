package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"regexp"
	"sync"
	"time"
)

var counter int
var targetFile string
var choose string
var threads int
var targetChan chan string = make(chan string)
var weakChan chan string = make(chan string, 3)
var writeFile string
var wg sync.WaitGroup
var mu sync.Mutex

//将匹配HTTP地址并输出至通道
//多线程从通道接收HTTP地址并判断405
//通道接收405地址写入文件

// 从从文件中读取并匹配URL
func readFile(targetFile string) {
	defer wg.Done()
	if targetFile == "" {
		fmt.Println("请输入文件路径，-r参数")
		os.Exit(0)
	}

	// 匹配文件中http或https开头的url
	fileHandle, err := os.Open(targetFile)
	if err != nil {
		panic(err)
	}
	defer fileHandle.Close()
	targetContentByte, err := ioutil.ReadAll(fileHandle)
	if err != nil && err != io.EOF {
		panic(err)
	}
	stringTargetContent := string(targetContentByte)
	matchURL := `http[s]?:\/\/\S[^'",“‘，。]+`
	reMatchURL := regexp.MustCompile(matchURL)
	targetSlice := reMatchURL.FindAllString(stringTargetContent, -1)
	for _, target := range targetSlice {
		targetChan <- target
	}
	close(targetChan)
	// fmt.Println("readFileReturn")
}

// 漏洞验证模块
func poc() {
	defer wg.Done()
	for {
		select {
		case target := <-targetChan:
			if target != "" {
				target = target + `/ui/vropspluginui/rest/services/uploadova`
				// fmt.Println(target, "URL拼接")
				req, err := http.NewRequest("GET", target, nil)
				if err != nil {
					panic(err)
				}
				Useragent := `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36`
				req.Header.Add("User-Agent", Useragent)
				req.Header.Add("Referer", `http://www.google.com/`)
				req.Header.Add("Cache-Control", `no-cache`)
				req.Header.Add("Pragma", `no-cache`)

				//跳过安全证书检查，设置超时
				tr := &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
					Dial: func(netw, addr string) (net.Conn, error) {
						conn, err := net.DialTimeout(netw, addr, time.Second*5)
						if err != nil {
							return nil, err
						}
						conn.SetDeadline(time.Now().Add(time.Second * 5))
						return conn, nil
					},
					ResponseHeaderTimeout: time.Second * 5,
				}

				client := &http.Client{Transport: tr}
				rep, err := client.Do(req)
				if err != nil {
					fmt.Println(err)
					continue
				}
				defer rep.Body.Close()
				status := rep.StatusCode
				if status == 405 {
					weakChan <- target
				} else {
					continue
				}
			} else if target == "" {
				fmt.Println("漏洞验证子线程结束！")
				return
			}
		case <-time.After(time.Second * 1):
			fmt.Println("漏洞验证子线程通道读取超时强制结束！")
			return
		}
	}

}

// 记录存在漏洞的URL
func writeWeakURL(weakURL string) {
	// 正则匹配并重命名文件名，用以保存漏洞地址
	matchFilename := `[^\.\n\t\r\f]+`
	reMatchFilename := regexp.MustCompile(matchFilename)
	wrFilenameSlice := reMatchFilename.FindAllString(targetFile, 1)
	writeFile = wrFilenameSlice[0] + "漏洞地址列表.txt"

	mu.Lock() // 加上并发锁，防止多线程争抢写入
	fileHandle, _ := os.OpenFile(writeFile, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0755)
	defer fileHandle.Close()
	fileHandle.WriteString(weakURL + "\n")
	mu.Unlock() // 解锁
}

// Exploite模块，后面更新
//func exp()

func main() {
	defer close(weakChan)
	flag.StringVar(&choose, "c", "poc", "漏洞验证")
	flag.StringVar(&targetFile, "r", "", "文件路径")
	flag.IntVar(&threads, "t", 1, "指定线程数")
	flag.Parse()

	// 从文件中读取url
	wg.Add(1)
	fmt.Println("文件读取线程开启！")
	go readFile(targetFile)

	// poc多线程验证
	if choose == `poc` {
		for i := 0; i < threads; i++ { //多线程模式
			wg.Add(1)
			fmt.Println("漏洞验证子线程开启！")
			go poc()
		}
	}
	//exp模块后面再补充
	// if choose == `exp` {

	// }
	go func() {
		for {
			select {
			case <-time.After(time.Second * 10):
			case weakURL := <-weakChan:
				fmt.Println(weakURL)
				if weakURL != "" {
					writeWeakURL(weakURL)
				}
			}
		}
	}()
	wg.Wait()
	time.Sleep(time.Second * 3) // writeWeakURL未设置wg.add，等待所有HTTP子线程死亡三秒后结束，防止数据写入不完整。
	fmt.Println("漏洞列表保存在:" + writeFile)
}
