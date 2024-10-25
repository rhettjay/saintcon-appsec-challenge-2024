import "./style.css";

import { useState, useRef, useEffect } from "preact/hooks";
import { ApiClient } from "./client";
import { Room, User } from "./model";
import { v4 as uuidv4 } from 'uuid';

function RoomView() {
  const [ws, setWs] = useState<WebSocket | undefined>(undefined);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [fileName, setFileName] = useState<string | null>(null);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState("");
  const [users, setUsers] = useState(new Map());
  const [rooms, setRooms] = useState([]);
  const [room, setRoom] = useState<Room | undefined>(undefined);
  const [user, setUser] = useState<User | undefined>(undefined);
  const [roomName, setRoomName] = useState("");
  const [usernameToAdd, setUsernameToAdd] = useState("");
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const formRef = useRef(null);
  const apiClient = new ApiClient();

  useEffect(() => {
    apiClient.getMe().then((u: User) => {
      if (u) {
        setUser(u);
      } else {
        window.location.href = "/login";
      }
    });
  }, []);

  useEffect(() => {
    if (!room) {
      return;
    }
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.close();
    }
    apiClient.getConnectionToken(room.roomId).then((token) => {
      setMessages([]);
      const host = new URL(window.location.href).host;
      const x = new WebSocket(
        `ws://${host}/ws?user=${user.userId}&token=${token}`
      );
      x.onmessage = (event) => {
        const messageData = JSON.parse(event.data);
        setMessages((prevMessages) => [...messageData, ...prevMessages]);
      };
      setWs(x);
    });
  }, [room]);

  useEffect(() => {
    if (!ws) {
      return;
    }
    ws.onmessage = (event) => {
      const messageData = JSON.parse(event.data);
      setMessages((prevMessages) => [...messageData, ...prevMessages]);
    };
  }, [ws, users]);
  
  const updateRooms = () => {
    apiClient.getMyRooms().then((rooms: Room[]) => {
      setRooms(rooms);
      setRoom(rooms[rooms.length - 1]);
    });
  };

  useEffect(() => {
    updateRooms();
  }, []);

  useEffect(() => {
    if (!room) {
      return;
    }
    apiClient.getRoomUsers(room.roomId).then((us: User[]) => {
      const umap = new Map();
      us.forEach((user) => {
        umap.set(user.userId.toString(), user);
      });
      setUsers(umap);
    });
  }, [room]);

  const handleSubmit = (e) => {
    e.preventDefault();
    const msg = { text: input, timestamp: new Date() };
    if (fileInputRef.current && fileInputRef.current.files && fileName) {
      const uid = uuidv4();
      const ext = fileName.split(".").pop();
      const fileId = `${uid}.${ext}`;
      uploadFile(fileInputRef.current.files[0], fileId);
      msg["fileName"] = fileName;
      msg["fileLocation"] = fileId;
    }
    ws.send(JSON.stringify(msg));
    setInput("");
    setFileName("");
  };

  // Fancy logic to handle ctrl + enter like discord
  const handleKeyDown = (e: KeyboardEvent) => {
    if (e.target instanceof HTMLTextAreaElement) {
      if (e.key === "Enter" && e.ctrlKey) {
        e.preventDefault();
        // Insert newline at current cursor position
        const start = e.target.selectionStart;
        const end = e.target.selectionEnd;
        setInput(input.slice(0, start) + "\n" + input.slice(end));

        // Move cursor to the end of the new line
        e.target.setSelectionRange(start + 1, start + 1);
      } else if (e.key === "Enter") {
        // Text areas dont submit by default
        e.preventDefault();
        formRef.current.requestSubmit();
      }
    }
  };

  useEffect(() => {
    if (textareaRef.current) {
      textareaRef.current.style.height = "1px";
      textareaRef.current.style.height = `${textareaRef.current.scrollHeight}px`;
    }
  }, [input]);

  const createRoom = async () => {
    if (roomName != "") {
      const r = await apiClient.createRoom(roomName);
      setRoom(r);
    } else {
      //todo error
    }
  };

  const deleteRoom = async (room: Room) => {
    if (confirm("Are you sure you want to delete room " + room.name + "?")) {
      await apiClient.deleteRoom(room.roomId);
      updateRooms();
    }
  };

  const deleteUser = async (u: User) => {
    if (
      confirm(
        "Are you sure you want to remove user " +
        u.username +
        " from this room?"
      )
    ) {
      await apiClient.removeUserFromRoom(room.roomId, u.userId);
      updateRooms();
    }
  };

  const addUserToRoom = async () => {
    if (usernameToAdd != "") {
      const newUser = await apiClient.addUserToRoom(room.roomId, usernameToAdd);
      if (!newUser) {
        alert("User could not be added")

      }
      const uid = newUser.userId;
      setUsers((prevUsers) => {
        const x = new Map(Array.from(prevUsers.entries()));
        x.set(uid, newUser);
        return x;
      });
    } else {
      alert("User could not be added")
    }
  };

  const handleIconClick = () => {
    if (fileInputRef.current) {
      fileInputRef.current.click();
    }
  };

  const handleFileChange = (event: Event) => {
    const target = event.target as HTMLInputElement;
    if (target.files && target.files.length > 0) {
      setFileName(target.files[0].name);
    }
  };

  const uploadFile = async (file: File, fileId: string) => {
    const formData = new FormData();
    formData.append('file', file);
    formData.append("filename", fileId);
    try {
      const response = apiClient.uploadFile(formData);

      if (!response) {
        alert('Failed to upload file.');
      }
    } catch (error) {
      alert('Failed to upload file.');
      console.error('Upload error:', error);
    }
  };

  const isImage = (fname) => {
    console.log(fname);
    const ext: string = fname.split(".").pop();
    const imageExtensions = ["png", "svg", "jpeg", "jpg", "webp"];
    console.log(imageExtensions.includes(ext));
    return imageExtensions.includes(ext);
  }

  return (
    <div class="chat-room">
      <h1 style="text-align: center">{room?.name}</h1>
      <div class="message-user-holder">
        <div class="room-list">
          <h3>Rooms</h3>
          {rooms?.map((room: Room) => (
            <div class="room-item" onClick={(e) => setRoom(room)}>
              <span id={"room-" + room.roomId.toString()}>{room.name}</span>
              {room?.hostId == user?.userId && (
                <span
                  style="float:right"
                  onClick={(e) => {
                    e.preventDefault();
                    deleteRoom(room);
                  }}
                >
                  X
                </span>
              )}
            </div>
          ))}
          <form>
            <div style={{ marginBottom: "1em" }}>
              <label for="roomName">Name:</label>
              <input
                type="text"
                id="roomName"
                value={roomName}
                onInput={(e) => setRoomName(e.target.value)}
                required
                style={{ padding: "0.5em", margin: "0.5em" }}
              />
            </div>
            <button
              onClick={(e) => {
                e.preventDefault();
                createRoom();
              }}
              class="button"
            >
              Create Room
            </button>
          </form>
        </div>
        <div class="message-area">
          <form onSubmit={(e) => {handleSubmit(e)}} class="input-area" ref={formRef}>
            <textarea
              ref={textareaRef}
              value={input}
              onInput={(e) => setInput((e.target as HTMLTextAreaElement).value)}
              onKeyDown={handleKeyDown}
            />
            <input type="file" style="display:none" ref={fileInputRef} onChange={handleFileChange} />
            <button
              type="button"
              onClick={handleIconClick}
              style={{
                border: 'none',
                background: 'transparent',
                cursor: 'pointer',
                padding: '0 8px',
              }}
              aria-label="Upload File"
            >
              📎
            </button>
            <button type="submit">Send</button>
          </form>
          {messages?.map((msg) => (
            <div class="message" style={{ color: msg.color || "inherit" }}>
              [
              {(msg.timestamp &&
                new Date(msg.timestamp).toLocaleTimeString()) ||
                "N/A"}
              ]{" "}
              <span class="username">
                {users.get(msg.userId)?.username || "NoUserProvided"}:
              </span>{" "}
              {msg.text ?? "invaid message format"}
              {msg.fileLocation && <div><span style="padding:2px"><a href={"/files/?path=" + msg.fileLocation}>{msg.fileName}</a></span>{isImage(msg.fileName) && <div><img src={"/files/?path=" + msg.fileLocation} style="width:100%;max-width:200px"></img></div>}</div> }
            </div>
          ))}
          <div />
        </div>
        <div class="user-list">
          <h3>Users</h3>
          <h5>(limit 5 + host)</h5>
          {Array.from(users.values()).map((u: User) => (
            <div class="room-item">
              {u.name} ({u.username}){" "}
              {room?.hostId == user?.userId && u?.userId != user?.userId && (
                <span
                  style="float:right"
                  onClick={(e) => {
                    e.preventDefault();
                    deleteUser(u);
                  }}
                >
                  X
                </span>
              )}
            </div>
          ))}
          <form>
            <div style={{ marginBottom: "1em" }}>
              <label for="usernameToAdd">Name:</label>
              <input
                type="text"
                id="usernameToAdd"
                value={usernameToAdd}
                onInput={(e) => setUsernameToAdd(e.target.value)}
                required
                style={{ padding: "0.5em", margin: "0.5em" }}
              />
            </div>
            <button onClick={(e) => { e.preventDefault(); addUserToRoom() }} class="button">
              Add user
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}

export default RoomView;
