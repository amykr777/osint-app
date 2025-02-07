/* Google Font */
@import url('https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;600&display=swap');

* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
  font-family: 'Poppins', sans-serif;
}

body {
  background-color: #121212;
  color: #fff;
  display: flex;
  justify-content: center;
  align-items: center;
  height: 100vh;
  padding: 20px;
}

.container {
  background: #1e1e1e;
  padding: 20px;
  border-radius: 12px;
  width: 100%;
  max-width: 500px;
  box-shadow: 0 4px 10px rgba(255, 255, 255, 0.1);
  text-align: center;
}

h1 {
  font-size: 24px;
  margin-bottom: 10px;
}

p {
  font-size: 14px;
  color: #bbb;
}

.input-group {
  display: flex;
  margin-top: 15px;
}

input {
  flex: 1;
  padding: 12px;
  border: none;
  border-radius: 8px 0 0 8px;
  outline: none;
  font-size: 16px;
}

.analyze-btn {
  padding: 12px 20px;
  background: #ff9800;
  color: white;
  border: none;
  border-radius: 0 8px 8px 0;
  cursor: pointer;
  font-size: 16px;
  transition: 0.3s;
}

.analyze-btn:hover {
  background: #e68900;
}

.result-box {
  background: #222;
  padding: 15px;
  border-radius: 8px;
  margin-top: 15px;
  text-align: left;
  font-size: 14px;
  white-space: pre-line; /* Preserves line breaks */
  display: none;
  word-wrap: break-word;
}

.copy-btn {
  margin-top: 10px;
  background: #4CAF50;
  color: white;
  border: none;
  padding: 10px;
  font-size: 14px;
  border-radius: 6px;
  cursor: pointer;
  display: none;
  width: 100%;
  transition: 0.3s;
}

.copy-btn:hover {
  background: #43a047;
}

/* Responsive Design */
@media (max-width: 500px) {
  .container {
    padding: 15px;
  }

  input, .analyze-btn {
    font-size: 14px;
    padding: 10px;
  }
}
