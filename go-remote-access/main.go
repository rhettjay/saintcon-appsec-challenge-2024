package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

func readAuthFile() map[string]string {
	body, _ := os.ReadFile("users.txt")
	text := string(body)
	userMap := make(map[string]string)
	for _, line := range strings.Split(text, "\n") {
		split := strings.SplitN(strings.TrimSpace(line), ":", 2)
		username := split[0]
		password := split[1]
		userMap[username] = password
	}
	return userMap
}

// My professor said not to use global variables but I think I'm fine here
var userMap = readAuthFile()

func authUser(c net.Conn) string {
	for {
		c.Write([]byte("Username: "))
		username, _ := bufio.NewReader(c).ReadString('\n')
		username = strings.TrimSpace(username)
		c.Write([]byte("Password: "))
		password, _ := bufio.NewReader(c).ReadString('\n')
		password = strings.TrimSpace(password)
		if password != "" && userMap[username] == password {
			c.Write([]byte("successful auth. Can run commands now.\n" + username + "$ "))
			return username
		}
	}
}

func execute(cmd string) string {
	result := exec.Command("/bin/sh", "-c", cmd)
	stdout, err := result.Output()

	out := string(stdout)
	if err != nil {
		out += "\nerror: " + err.Error() + "\n"
	}
	return out
}

func handleConnection(c net.Conn) {
	defer c.Close()
	var authedUsername = authUser(c)
	for {
		line, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			fmt.Println(err)
			return
		}

		cmd := strings.TrimSpace(line)
		if cmd == "exit!" {
			authedUsername = ""
			return
		}

		result := execute(cmd)
		c.Write([]byte(result))
		c.Write([]byte(authedUsername + "$ "))
	}
}

func main() {
	host := "0.0.0.0:" + os.Args[1]
	l, err := net.Listen("tcp", host)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer l.Close()

	for {
		c, err := l.Accept()
		if err != nil {
			fmt.Println(err)
			return
		}
		go handleConnection(c)
	}
}
