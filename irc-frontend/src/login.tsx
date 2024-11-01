import "./style.css";

import { useState } from "preact/hooks";
import { ApiClient } from "./client";

function Login() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const apiClient = new ApiClient();

  const handleSubmit = async (e) => {
    e.preventDefault();
    const response = await apiClient.login(username, password);
    if (response) {
      //navigate to the next page
      const next = window.location.href.split("?").pop().split("&").map((x) => x.split("=")).find((x) => x[0] == "next");
      if (next?.length > 0) {
        window.location.href = next[1];
      } else {
        window.location.href = "/";
      }
    } else {
      //todo wrong password
    }
  };


  return (
    <div class="login-page">
      <div class="login-container">
        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: '1em' }}>
            <label for="username">Username:</label>
            <input
              type="text"
              id="username"
              value={username}
              onInput={(e) => setUsername(e.target.value)}
              required
              style={{ width: '100%', padding: '0.5em', margin: '0.5em 0' }}
            />
          </div>
          <div style={{ marginBottom: '1em' }}>
            <label for="password">Password:</label>
            <input
              type="password"
              id="password"
              value={password}
              onInput={(e) => setPassword(e.target.value)}
              required
              style={{ width: '100%', padding: '0.5em', margin: '0.5em 0' }}
            />
          </div>
          <button type="submit" style="padding:10px">Login</button>
          <a href="/signup" style="margin-left:100px">I don't have an account</a>
        </form>
      </div>
    </div>
  );
}

export default Login;