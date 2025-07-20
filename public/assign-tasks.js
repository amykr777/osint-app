// assign-tasks.js

const USER_FULLNAMES = {
    "Aman": "Aman Kumar",
    "Aditya": "Aditya Udgaonkar",
    "Ajinkya": "Ajinkya Kadam",
    "Akshat": "Akshat Jain",
    "Akshay": "Akshay Khade",
    "Anant": "Anant Jain",
    "Devyani": "Devyani Itware",
    "Dnyanaraj": "Dnyanaraj Desai",
    "Mayank": "Mayank Attri",
    "Prateek": "Prateek Aujkar"
  };
  
  // Assign explicit CSS class for each user
  const USER_BADGE_CLASS = {
    "Aman": "badge-aman",
    "Aditya": "badge-aditya",
    "Ajinkya": "badge-ajinkya",
    "Akshat": "badge-akshat",
    "Akshay": "badge-akshay",
    "Anant": "badge-anant",
    "Devyani": "badge-devyani",
    "Dnyanaraj": "badge-dnyanaraj",
    "Mayank": "badge-mayank",
    "Prateek": "badge-prateek"
  };
  
  let users = [], tasks = [], prodTimes = {}, present = {}, assignments = {};
  
  function getUserBadge(username) {
    const className = USER_BADGE_CLASS[username] || "bg-light text-dark";
    let fullname = USER_FULLNAMES[username] || username;
    let initials = '';
    if (fullname.split(' ').length > 1) {
      initials = fullname.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2);
    } else {
      initials = username.slice(0, 2).toUpperCase();
    }
    return `<span class="badge rounded-pill ${className} me-1 p-2" style="font-size:1em;">
      <i class="fas fa-user-circle me-1"></i>${initials} <span class="fw-normal">${fullname}</span>
    </span>`;
  }
  
  // ------- LOADERS -------
  async function loadData() {
    users = await fetch('/api/task-users').then(res => res.json());
    tasks = await fetch('/api/task-list').then(res => res.json());
    prodTimes = await fetch('/api/task-prod-times').then(res => res.json());
    present = await fetch('/api/task-presence').then(res => res.json());
    showUsers(); showTasks(); showAssignments();
  }
  
  // ------- USERS & TASKS DISPLAY -------
  function showUsers() {
    let par = document.getElementById('userChips'); par.innerHTML = '';
    users.forEach(u => {
      let d = document.createElement('div');
      d.className = 'user-chip' + (!present[u] ? ' absent' : '');
      d.innerHTML = `
        <label><input type="checkbox" class="form-check-input me-1" style="vertical-align: middle"
          ${present[u] ? 'checked' : ''}
          onchange="toggleUserPresent('${u}')">
          ${USER_FULLNAMES[u] || u}
        </label>
      `;
      par.appendChild(d);
    });
  }
  
  function showTasks() {
    let html = `<tr><th>Task</th><th>Prod Time (min)</th></tr>`;
    html += tasks.map(t =>
      `<tr>
        <td>${t}</td>
        <td>${prodTimes[t] || ''}</td>
      </tr>`
    ).join('');
    document.getElementById('taskTable').innerHTML = html;
  }
  
  // ------- ASSIGNMENTS TABLE -------
  function showAssignments() {
    let container = document.getElementById('assignmentTableContainer');
    let placeholder = document.getElementById('assignmentPlaceholder');
    let taskMap = {};
    if (assignments && Object.keys(assignments).length) {
      for (let user in assignments) {
        assignments[user].forEach(item => {
          if (!taskMap[item.task]) taskMap[item.task] = { users: [], prod: item.prod };
          if (!taskMap[item.task].users.includes(user)) taskMap[item.task].users.push(user);
          if (item.task === "Failed ARPs") taskMap[item.task].prod = "5 (per ARP)";
        });
      }
    }
    let html = `
      <div class="table-responsive">
        <table class="table table-bordered table-sm align-middle mb-0">
          <thead>
            <tr>
              <th>Task Name</th>
              <th>Assigned To</th>
              <th>Prod. Time (min)</th>
            </tr>
          </thead>
          <tbody>
            ${
              tasks.map(t =>
                `<tr>
                  <td>${t}</td>
                  <td>${
                    (taskMap[t] && taskMap[t].users.length)
                      ? taskMap[t].users.map(username => getUserBadge(username)).join(' ')
                      : ''
                  }</td>
                  <td>${taskMap[t] && taskMap[t].users.length ? (taskMap[t].prod !== undefined ? taskMap[t].prod : '') : ''}</td>
                </tr>`
              ).join('')
            }
          </tbody>
        </table>
      </div>
    `;
    if (!Object.keys(taskMap).length) {
      placeholder.style.display = '';
      container.innerHTML = '';
    } else {
      placeholder.style.display = 'none';
      container.innerHTML = html;
    }
  }
  
  function toggleUserPresent(u) {
    present[u] = !present[u];
    fetch('/api/task-presence', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(present)
    });
    showUsers();
  }
  
  // ------- MODAL EDITING -------
  document.getElementById('editUsersModal').addEventListener('show.bs.modal', function () {
    document.getElementById('editUsersInput').value = users.join('\n');
  });
  document.getElementById('editTasksModal').addEventListener('show.bs.modal', function () {
    document.getElementById('editTasksInput').value = tasks.join('\n');
  });
  document.getElementById('editProdModal').addEventListener('show.bs.modal', function () {
    let cont = document.getElementById('editProdContainer');
    cont.innerHTML = '';
    tasks.forEach((t, i) => {
      let row = document.createElement('div');
      row.className = 'mb-2 input-group';
      row.innerHTML = `
        <span class="input-group-text w-50">${t}</span>
        <input type="number" class="form-control" id="prod_${i}" value="${prodTimes[t] || ''}" min="0">
        <span class="input-group-text">min</span>`;
      cont.appendChild(row);
    });
  });
  
  window.saveUsersEdit = function () {
    let val = document.getElementById('editUsersInput').value.trim();
    let us = val ? val.split('\n').map(x => x.trim()).filter(Boolean) : [];
    fetch('/api/task-users', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ users: us })
    }).then(() => { bootstrap.Modal.getInstance(document.getElementById('editUsersModal')).hide(); loadData(); });
  };
  window.saveTasksEdit = function () {
    let val = document.getElementById('editTasksInput').value.trim();
    let ts = val ? val.split('\n').map(x => x.trim()).filter(Boolean) : [];
    fetch('/api/task-list', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ tasks: ts })
    }).then(() => { bootstrap.Modal.getInstance(document.getElementById('editTasksModal')).hide(); loadData(); });
  };
  window.saveProdEdit = function () {
    let inputs = document.querySelectorAll("#editProdContainer input[type='number']");
    let obj = {};
    tasks.forEach((t, i) => obj[t] = parseInt(inputs[i].value) || 0);
    fetch('/api/task-prod-times', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(obj)
    }).then(() => { bootstrap.Modal.getInstance(document.getElementById('editProdModal')).hide(); loadData(); });
  };
  
  // ------- ASSIGN & SHUFFLE BUTTON -------
  async function assignTasks() {
    const pres = Object.keys(present).filter(u => present[u]);
    assignments = await fetch('/api/assign-tasks', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ present: pres })
    }).then(res => res.json());
    showAssignments();
  }
  async function shuffleTasks() { await assignTasks(); }
  
  window.onload = loadData;
  