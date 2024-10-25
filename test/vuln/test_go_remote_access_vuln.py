import socket

class TestGoRemoteAccessVuln:
    hostname = "remote-access"
    port = 8023

    def reset_connection(self, s = None):
        if not s:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((self.hostname, self.port))
        try:
            s.recv(1024)
        except Exception as e:
            s.send(b"exit!\n")
            pass
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((self.hostname, self.port))
        s.recv(1024)
        return s

    def test_GO_EASY(self):
        s = self.reset_connection()
        s.send(b"sketrik\n")
        s.recv(1024)
        s.send(b"sekure\n")
        s.recv(1024)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((self.hostname, self.port))
        s.send(b"whoami\n")
        assert b"root" not in s.recv(1024)

    def test_GO_HARD(self):
        """
        Can login with blank username/password
        """
        s = self.reset_connection()
        s.send(b"\n")
        s.recv(1024)
        s.send(b"\n")
        s.recv(1024)
        s.send(b"whoami\n")
        assert b"root" not in s.recv(1024)
        s.send(b"exit!\n")
        s.close()