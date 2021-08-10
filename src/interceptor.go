package main

import (
	"os"
	"io"
	"fmt"
	"bufio"
	"bytes"
	"net"
	"time"
	"strings"
	"errors"
	"regexp"
	"syscall"

	"net/http"
	"os/signal"
	"io/ioutil"
	"math/rand"
	"encoding/json"
	"path/filepath"

	"gopkg.in/yaml.v2"
	"github.com/gorilla/mux"
	"github.com/go-gomail/gomail"
)

type Email struct {
	To []string
	From string
	Subject string `json:"-"`
	StrData string
	Data bytes.Buffer `json:"-"`

	RemoteName string `json:"-"`
	RemoteIP string `json:"-"`
	RemoteHost string `json:"-"`

	HasTo bool `json:"-"`
	HasFrom bool `json:"-"`
	HasSubject bool `json:"-"`
	HasData bool `json:"-"`
}

type Config struct {
	StreamToSplunk bool `yaml:"stream_to_splunk"`
	SplunkServers []string `yaml:"splunk_servers"`
	SplunkTimeout int `yaml:"splunk_timeout"`
	Subjects []string `yaml:"subjects"`
	Blackholes []string `yaml:"blackholes"`
	SMTPServer string `yaml:"smtp_server"`
	SMTPPort int `yaml:"smtp_port"`
	FilePath string `yaml:"file_path"`
}

var configpath string
var cfg Config

func EventStream(message string) error {
	sentflag := false

	body := strings.Split(message, "\r\n\r\n")
	message = body[0]
	message = strings.Replace(message, "\r\n", "\n", -1)
	message = strings.Replace(message, "\n", "|", -1)
	message = message + "|" + body[1]
	message = strings.Replace(message, "||", "|", -1)

	for ! sentflag {
		for _, server := range cfg.SplunkServers {
			conn, err := net.DialTimeout("tcp", server, time.Duration(cfg.SplunkTimeout) * time.Second)
			if err != nil {
				continue
			}

			fmt.Fprint(conn, message)
			conn.Close()
			sentflag = true
			break
		}

		if ! sentflag {
			time.Sleep(1 * time.Minute)
		}
	}

	return nil
}

func Log(message string) error {

	fmt.Println(message)
/*
        file, err := os.OpenFile("/var/log/interceptor.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
        if err != nil {
                fmt.Println("failed to open log file: " + err.Error())
                return err
        }
        defer file.Close()

        current_time := time.Now().Local()
        t := current_time.Format("Jan 02 2006 03:04:05")
        _, err = file.WriteString(t + "|Interceptor|" + message + "\n")

        if err != nil {
                fmt.Println("failed to write to log file: " + err.Error())
                return err
        }
*/
        return nil
}

func RandomString(length int) string {
        rand.Seed(time.Now().UnixNano())
        var list = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")

        chars := make([]rune, length)
        for i := range chars {
                chars[i] = list[rand.Intn(len(list))]
        }

        return string(chars)
}

func Read(nConn net.Conn) (string, error) {
	var buffer bytes.Buffer
	rdr := bufio.NewReader(nConn)

	nConn.SetReadDeadline(time.Now().Add(15 * time.Second))

	for {
		ba, pref, err := rdr.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", err
		}

		buffer.Write(ba)
		if ! pref {
			break
		}
	}

	return buffer.String(), nil
}

func Write(nConn net.Conn, content string) (int, error) {
	writer := bufio.NewWriter(nConn)
	b, err := writer.WriteString(content)
	if err == nil {
		err = writer.Flush()
	}

	return b, err
}

func Check(nConn net.Conn, line string, email *Email) (error) {
	verb := ""
	args := ""

	if idx := strings.Index(line, " "); idx != -1 {
		verb = strings.ToUpper(line[:idx])
		args = strings.TrimSpace(line[idx+1:])
	} else {
		verb = strings.ToUpper(line)
		args = ""
	}

	verb = strings.Replace(verb, ":", " ", -1)
	args = strings.Replace(args, ":", " ", -1)

	email.RemoteIP, _, _ = net.SplitHostPort(nConn.RemoteAddr().String())
	n, err := net.LookupAddr(email.RemoteIP)
	
	if err == nil && len(n) > 0 {
		email.RemoteHost = n[0]
	} else {
		email.RemoteHost = "unknown"
	}

	switch verb {
	case "HELO":
		Write(nConn, "250 cac greets " + args + "\n")
		email.RemoteName = args
	case "MAIL":
		if args == "" {
			Write(nConn, "501 5.5.4 Syntax error in parameters or arguments (invalid FROM params)\n")
			return nil
		}
		
		if ! strings.Contains(args, " ") {
			Write(nConn, "501 5.5.4 Syntax error in parameters or arguments (invalid FROM params)\n")
			return nil
		}

		re_leadclose_whtsp := regexp.MustCompile(`^[\s\p{Zs}]+|[\s\p{Zs}]+$`)
		re_inside_whtsp := regexp.MustCompile(`[\s\p{Zs}]{2,}`)
		args = re_leadclose_whtsp.ReplaceAllString(args, "")
		args = re_inside_whtsp.ReplaceAllString(args, " ")

		args = strings.TrimSpace(strings.Replace(args, " ", " ", -1))
		parts := strings.Split(args, " ")

		if strings.ToUpper(parts[0]) != "FROM" {
			Write(nConn, "501 5.5.4 Syntax error in parameters or arguments (invalid FROM params)\n")
			return nil
		}

		email.From = parts[1]
		email.HasFrom = true

		Write(nConn, "250 2.1.5 Ok\n")
	case "RCPT":
		if args == "" {
			Write(nConn, "501 5.5.4 Syntax error in parameters or arguments (args empty)\n")
			return nil
		}
		
		if ! strings.Contains(args, " ") {
			Write(nConn, "501 5.5.4 Syntax error in parameters or arguments (missing space)\n")
			return nil
		}

		re_leadclose_whtsp := regexp.MustCompile(`^[\s\p{Zs}]+|[\s\p{Zs}]+$`)
		re_inside_whtsp := regexp.MustCompile(`[\s\p{Zs}]{2,}`)
		args = re_leadclose_whtsp.ReplaceAllString(args, "")
		args = re_inside_whtsp.ReplaceAllString(args, " ")

		parts := strings.Split(args, " ")

		if strings.ToUpper(parts[0]) != "TO" {
			Write(nConn, "501 5.5.4 Syntax error in parameters or arguments (invalid TO params)\n")
			return nil
		}

		if (len(parts) - 1) >= 100 {
			Write(nConn, "452 4.5.3 Too many recipients\n")
			return nil
		}

		for i := 1; i < len(parts); i++ {
			email.To = append(email.To, parts[i])
		}

		email.HasTo = true
		Write(nConn, "250 2.1.5 Ok\n")

	case "RSET":
		Write(nConn, "250 2.0.0 Ok\n")

		email.To = nil
		email.From = ""
		email.StrData = ""
		email.HasFrom = false
		email.HasTo = false
		email.HasSubject = false
		email.HasData = false
		email.Data.Reset()
	case "DATA":
		var data []byte
		rdr := bufio.NewReader(nConn)

		if email.HasTo == false || email.HasFrom == false {
			Write(nConn, "503 5.5.1 Bad sequence of commands (MAIL & RCPT required before DATA)\n")
		}
		
		Write(nConn, "354 Start Mail Input; End With <CR><LF>.<CR><LF>\n")

		for {
			nConn.SetReadDeadline(time.Now().Add(15 * time.Second))
			
			line, err := rdr.ReadBytes('\n')
			if err != nil {
				Log("crap")
				return err
			}

			if bytes.Equal(line, []byte(".\r\n")) {
				break;
			}

			if line[0] == '.' {
				line = line[1:]
			}

			data = append(data, line...)
		}

		email.Data.Reset()
		email.Data.Write(data)

		Write(nConn, "250 2.0.0 Ok: Queued\n")

	case "NOOP":
		Write(nConn, "250 2.0.0 Uuuuh, Ok.\n")
	case "QUIT":
		Write(nConn, "250 2.0.0 C-Ya\n")
		return errors.New("Quit")
	default:
		Write(nConn, "500 5.5.2 Syntax error, command unrecognized\n")
	}



	return nil
}

func MakeHeaders(email *Email) []byte {
	var buffer bytes.Buffer
	hname, _ := os.Hostname()
	now := time.Now().Format("Mon, _2 Jan 2006 15:04:05 -0700 (MST)")
	buffer.WriteString(fmt.Sprintf("Received: from %s (%s [%s])\r\n", email.RemoteName, email.RemoteHost, email.RemoteIP))
	buffer.WriteString(fmt.Sprintf("        by %s (%s) with SMTP\r\n", hname, "cac2sms"))
	buffer.WriteString(fmt.Sprintf("        for <%s>; %s\r\n", email.To[0], now))
	return buffer.Bytes()
}

func WriteToFile(email *Email) {
	email.StrData = string(email.Data.Bytes())
	jsn, err := json.Marshal(email)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	filename := RandomString(32)
	err = ioutil.WriteFile(cfg.FilePath + filename, []byte(string(jsn)), 0644)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
}

func ForwardEmail(email *Email) {
	date := ""
	subject := ""
	messageid := ""
	contenttype := ""
	contentxfer := ""
	useragent := "Email.Interceptor"
	body := ""

	email.StrData = string(email.Data.Bytes())

	parts := strings.Split(email.StrData, "\n")
	bflag := false
	for _, part := range parts {
		if strings.HasPrefix(strings.ToLower(part), "te:") {
			sections := strings.Split(part, ":")
			date = sections[1]
		}

		if strings.HasPrefix(strings.ToLower(part), "subject:") {
			sections := strings.Split(part, ":")
			subject = sections[1]
		}

		if strings.HasPrefix(strings.ToLower(part), "message-id:") {
			sections := strings.Split(part, ":")
			messageid = sections[1]
		}

		if strings.HasPrefix(strings.ToLower(part), "content-type:") {
			sections := strings.Split(part, ":")
			contenttype = sections[1]
		}

		if strings.HasPrefix(strings.ToLower(part), "content-transfer-encoding:") {
			sections := strings.Split(part, ":")
			contentxfer = sections[1]
		}

		part = strings.TrimSpace(part)

		if part == "" {
			bflag = true
		}

		if bflag == true {
			body += part + "\r\n"
		}
	}

	m := gomail.NewMessage()
	m.SetHeader("Date", date)
	m.SetHeader("From", email.From)
	m.SetHeader("To", email.To[0])
	m.SetHeader("Subject", subject)
	m.SetHeader("Message-ID", messageid)
	m.SetHeader("User-Agent", useragent)
	m.SetHeader("Content-Type", contenttype)
	m.SetHeader("Content-Transfer-Encoding", contentxfer)
	m.SetBody("text/plain", body)

	d := gomail.Dialer{Host: cfg.SMTPServer, Port: cfg.SMTPPort, SSL: false, TLSConfig: nil}
	if err := d.DialAndSend(m); err != nil {
		Log("Error Sending To smtp.cac.com: " + err.Error())
		return
	}
}

func HandleConnection(nConn net.Conn) {
	var elist []string
	var subject string

	email := Email{}

	Write(nConn, "220 Interceptor ESMTP Service ready\n")

	for {
		line, err := Read(nConn)
		if err != nil {
			Write(nConn, "421 4.4.2 Interceptor ESMTP Service closing transmition: " + err.Error() + "\n")
			nConn.Close()
			break
		}

		err = Check(nConn, line, &email)
		if err != nil {
			nConn.Close()
			break
		}
	}

	for _, to := range email.To {

		to = strings.Replace(to, "<", "", -1)
		to = strings.Replace(to, ">", "", -1)

		elist = append(elist, to)
	}

	for _, e := range elist {
		nemail := Email{}
		nemail.To = append(nemail.To, e)
		nemail.From = email.From
		nemail.Data = email.Data

		StrData := string(nemail.Data.Bytes())
		parts := strings.Split(StrData, "\n")
		for _, part := range parts {
			if strings.HasPrefix(strings.ToLower(part), "subject:") {
				sections := strings.Split(part, ":")
				subject = sections[1]
			}
		}

		bhflag := false
		for _, bsubject := range cfg.Blackholes {
			if strings.ToLower(strings.TrimSpace(subject)) == strings.ToLower(strings.TrimSpace(bsubject)) {
				bhflag = true
			}
		}

		if bhflag {
			Log("Sent To Blackhole: To: " + nemail.To[0] + "~From: " + nemail.From + "~Subject: " + subject)
			continue
		}

		failflag := false
		for _, rsubject := range cfg.Subjects {
			if strings.ToLower(strings.TrimSpace(subject)) == strings.ToLower(strings.TrimSpace(rsubject)) {
				failflag = true
			}
		}

		if failflag {
			if cfg.StreamToSplunk {
				go EventStream(string(email.Data.Bytes()))
			} else {
				WriteToFile(&nemail)
			}
		} else {
			ForwardEmail(&nemail)
		}
	}
}

func handleWhoAreYou(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Interceptor\n")
}

func handlePing(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "pong\n")
}

func handleDescription(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Email Interceptor - Writes Emails To A Network Port Or Files Based On Subject\n")
}

func handleSubjects(w http.ResponseWriter, r *http.Request) {
	jsn, err := json.Marshal(cfg.Subjects)
	if err != nil {
		fmt.Fprintf(w, err.Error())
		return
	}

	fmt.Fprintf(w, string(jsn) + "\n")
}

func handleAddSubject(w http.ResponseWriter, r *http.Request) {
	subject := r.FormValue("subject")

	if len(subject) == 0 {
		fmt.Fprintf(w, "Missing Required Parameter 'subject'\n")
		return
	}

	cfg.Subjects = append(cfg.Subjects, subject)

	yml, err := yaml.Marshal(cfg)
	if err != nil {
		fmt.Fprintf(w, err.Error())
		return
	}

	err = ioutil.WriteFile(configpath, []byte(string(yml)), 0644)
	if err != nil {
		fmt.Fprintf(w, err.Error())
		return
	}

	fmt.Fprintf(w, "Success\n")
}

func handleDeleteSubject(w http.ResponseWriter, r *http.Request) {
	subject := r.FormValue("subject")

	if len(subject) == 0 {
		fmt.Fprintf(w, "Missing Required Parameter 'subject'\n")
		return
	}

        flag := false
        keep := -1
        for i:=0; i < len(cfg.Subjects); i++ {
		if strings.ToLower(cfg.Subjects[i]) == strings.ToLower(subject) {
                        flag = true
                        keep = i
                }
        }

        if ! flag {
                fmt.Fprintf(w, "No Matching Subject Found")
                return
        }

	cfg.Subjects = append(cfg.Subjects[:keep], cfg.Subjects[keep+1:]...)

	yml, err := yaml.Marshal(cfg)
	if err != nil {
		fmt.Fprintf(w, err.Error())
		return
	}

	err = ioutil.WriteFile(configpath, []byte(string(yml)), 0644)
	if err != nil {
		fmt.Fprintf(w, err.Error())
		return
	}

	fmt.Fprintf(w, "Success\n")
}


//---------------------------------
func handleBlackholes(w http.ResponseWriter, r *http.Request) {
	jsn, err := json.Marshal(cfg.Blackholes)
	if err != nil {
		fmt.Fprintf(w, err.Error())
		return
	}

	fmt.Fprintf(w, string(jsn) + "\n")
}

func handleAddBlackhole(w http.ResponseWriter, r *http.Request) {
	subject := r.FormValue("subject")

	if len(subject) == 0 {
		fmt.Fprintf(w, "Missing Required Parameter 'subject'\n")
		return
	}

	cfg.Blackholes = append(cfg.Blackholes, subject)

	yml, err := yaml.Marshal(cfg)
	if err != nil {
		fmt.Fprintf(w, err.Error())
		return
	}

	err = ioutil.WriteFile(configpath, []byte(string(yml)), 0644)
	if err != nil {
		fmt.Fprintf(w, err.Error())
		return
	}

	fmt.Fprintf(w, "Success\n")
}

func handleDeleteBlackhole(w http.ResponseWriter, r *http.Request) {
	subject := r.FormValue("subject")

	if len(subject) == 0 {
		fmt.Fprintf(w, "Missing Required Parameter 'subject'\n")
		return
	}

        flag := false
        keep := -1
        for i:=0; i < len(cfg.Blackholes); i++ {
		if strings.ToLower(cfg.Blackholes[i]) == strings.ToLower(subject) {
                        flag = true
                        keep = i
                }
        }

        if ! flag {
                fmt.Fprintf(w, "No Matching Subject Found")
                return
        }

	cfg.Blackholes = append(cfg.Blackholes[:keep], cfg.Blackholes[keep+1:]...)

	yml, err := yaml.Marshal(cfg)
	if err != nil {
		fmt.Fprintf(w, err.Error())
		return
	}

	err = ioutil.WriteFile(configpath, []byte(string(yml)), 0644)
	if err != nil {
		fmt.Fprintf(w, err.Error())
		return
	}

	fmt.Fprintf(w, "Success\n")
}

func handleLoadSubjects(w http.ResponseWriter, r *http.Request) {
	b, err := ioutil.ReadFile(configpath)
	if err != nil {
		fmt.Fprintf(w, "Error Opening File " + configpath + ": " + err.Error())
		return
	}

	err = yaml.Unmarshal([]byte(b), &cfg)
	if err != nil {
		fmt.Fprintf(w, "Couldn't Parse YAML File " + configpath + ": " + err.Error())
		return
	}

	fmt.Fprintf(w, "Success\n")
}

func handleWriteSubjects(w http.ResponseWriter, r *http.Request) {
	yml, err := yaml.Marshal(cfg)
	if err != nil {
		fmt.Fprintf(w, err.Error())
		return
	}

	err = ioutil.WriteFile(configpath, []byte(string(yml)), 0644)
	if err != nil {
		fmt.Fprintf(w, err.Error())
		return
	}

	fmt.Fprintf(w, "Success\n")
}

func main() {

        ex, err := os.Executable()
        if err != nil {
                fmt.Println(err.Error())
                return
        }

        expath := filepath.Dir(ex)
        configpath = "/etc/interceptor.yaml"
        if _, err := os.Stat(configpath); os.IsNotExist(err) {
                if _, ferr := os.Stat("./interceptor.yaml"); os.IsNotExist(ferr) {
                        configpath = expath + "/interceptor.yaml"
                } else {
                        configpath = "./interceptor.yaml"
                }
        }

        b, err := ioutil.ReadFile(configpath)
        if err != nil {
                Log("Error Opening File " + configpath + ": " + err.Error())
                return
        }

        yml := string(b)
        err = yaml.Unmarshal([]byte(yml), &cfg)

        if err != nil {
                Log("Couldn't Parse YAML File " + configpath + ": " + err.Error())
                return
        }

	signalChannel := make(chan os.Signal, 2)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGUSR1, syscall.SIGUSR2, syscall.SIGINT)
	go func() {
		for {
			sig := <-signalChannel
			switch sig {
			case syscall.SIGUSR1: 
			        b, err := ioutil.ReadFile(configpath)
			        if err != nil {
			                Log("Error Opening File " + configpath + ": " + err.Error())
					return
			        }

				err = yaml.Unmarshal([]byte(b), &cfg)
				if err != nil {
					Log("Couldn't Parse YAML File " + configpath + ": " + err.Error())
					return
				}
				fmt.Println("Reloaded Config")
			case syscall.SIGUSR2:
				yml, err := yaml.Marshal(cfg)
				if err != nil {
					fmt.Println(err.Error())
					return
				}
					
				err = ioutil.WriteFile(configpath, []byte(string(yml)), 0644)
				if err != nil {
					fmt.Println(err.Error())
					return
				}
				Log("Wrote File: " + configpath)
			case syscall.SIGINT:
				os.Exit(1)
			}
		}
	}()

	go func() {
		router := mux.NewRouter()
		router.HandleFunc("/whoareyou", handleWhoAreYou)
		router.HandleFunc("/ping", handlePing)
		router.HandleFunc("/description", handleDescription)
		router.HandleFunc("/getsubjects", handleSubjects)
		router.HandleFunc("/addsubject", handleAddSubject)
		router.HandleFunc("/deletesubject", handleDeleteSubject)
		router.HandleFunc("/getblackholes", handleBlackholes)
		router.HandleFunc("/addblackhole", handleAddBlackhole)
		router.HandleFunc("/deleteblackhole", handleDeleteBlackhole)
		router.HandleFunc("/loadconfig", handleLoadSubjects)
		router.HandleFunc("/writeconfig", handleWriteSubjects)

		err := http.ListenAndServe(":8080", router)
		if err != nil {
			fmt.Println("ListenAndServe: ", err)
		}
	}()

        listener, err := net.Listen("tcp", "0.0.0.0:25")
        if err != nil {
                fmt.Println("Error: " + err.Error())
                return
        }

        for {
                nConn, err := listener.Accept()
                if err != nil {
                        fmt.Println("Error: " + err.Error())
                        return
                }

                go HandleConnection(nConn)

        }
}

