package users

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

type UsersModule struct{}

type UserInfo struct {
	Username string   `json:"username"`
	UID      int      `json:"uid"`
	Groups   []string `json:"groups"`
	Shell    string   `json:"shell"`
}

func (m *UsersModule) Name() string {
	return "users"
}

func (m *UsersModule) Gather() (interface{}, error) {
	var users []UserInfo

	// Linux specific: parse /etc/passwd
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return users, nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, ":")
		if len(parts) >= 7 {
			uid, _ := strconv.Atoi(parts[2])
			// Only include real users (UID >= 1000) for brevity, or all
			if uid >= 1000 || uid == 0 {
				users = append(users, UserInfo{
					Username: parts[0],
					UID:      uid,
					Groups:   []string{}, // Groups would require parsing /etc/group
					Shell:    parts[6],
				})
			}
		}
	}

	return users, nil
}
