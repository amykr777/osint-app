// assign-tasks.js

const USER_FULLNAMES = {
  "Aman": "Aman Kumar",
  "Abhishek": "Abhishek Sabarinath",
  "Aditya": "Aditya Udgaonkar",
  "Ajinkya": "Ajinkya Kadam",
  "Akshat": "Akshat Jain",
  "Akshay": "Akshay Khade",
  "Anant": "Anant Jain",
  "Animesh": "Animesh Rai",
  "Devyani": "Devyani Itware",
  "Binu": "Binu Sharma",
  "Dnyanaraj": "Dnyanaraj Desai",
  "Mayank": "Mayank Attri",
  "Prateek": "Prateek Aujkar",
  "Savali": "Savali Varne",
  "Shivsai": "Shivsai Peddinti",
  "Shounak": "Shounak Das",
  "Shreyansh": "Shreyansh Swami",
  "Shreyas": "Shreyas Lolage",
  "Swapneel": "Swapneel Khandagale",
  "Tavish": "Tavish Negi",
  "Vishal": "Vishal Vasava"
};

// Assign explicit CSS class for each user
const USER_BADGE_CLASS = {
  "Aman": "badge-aman",
  "Abhishek": "badge-abhishek",
  "Aditya": "badge-aditya",
  "Ajinkya": "badge-ajinkya",
  "Akshat": "badge-akshat",
  "Akshay": "badge-akshay",
  "Anant": "badge-anant",
  "Animesh": "badge-animesh",
  "Devyani": "badge-devyani",
  "Binu": "badge-binu",
  "Dnyanaraj": "badge-dnyanaraj",
  "Mayank": "badge-mayank",
  "Prateek": "badge-prateek",
  "Savali": "badge-savali",
  "Shivsai": "badge-shivsai",
  "Shounak": "badge-shounak",
  "Shreyansh": "badge-shreyansh",
  "Shreyas": "badge-shreyas",
  "Swapneel": "badge-swapneel",
  "Tavish": "badge-tavish",
  "Vishal": "badge-vishal",
};

let users = [], tasks = [], prodTimes = {}, present = {}, assignments = {};

// ---- Canonical task model (names/times/caps) ----
const CANONICAL_TASKS = [
  { name: "Call log audit",           time: 30, max: 5 },
  { name: "Customer response",        time: 60, max: 5 },
  { name: "Unassigned queue",         time: 40, max: 5 },
  { name: "Informationals",           time: 20, max: 5 },
  { name: "Phone",                    time: 30, max: 5 }, // must match Call log audit users
  { name: "Trinity Phishing mailbox", time: 60, max: 2 },
  { name: "Hyatt EoG",                time: 25, max: 2 },
  { name: "Failed ARPs",              time: 0,  max: 2 }, // 5 per ARP, not counted in balance
  { name: "St. Jude",                 time: 25, max: 2 }
];
const CANONICAL_TIMES = Object.fromEntries(CANONICAL_TASKS.map(t => [t.name, t.time]));
const CANONICAL_NAMES = CANONICAL_TASKS.map(t => t.name);

// ------- LOCALSTORAGE HELPERS -------
function saveData() {
  localStorage.setItem("users", JSON.stringify(users));
  localStorage.setItem("tasks", JSON.stringify(tasks));
  localStorage.setItem("prodTimes", JSON.stringify(prodTimes));
  localStorage.setItem("present", JSON.stringify(present));
}

function loadSavedData() {
  // users
  users = JSON.parse(localStorage.getItem("users")) || Object.keys(USER_FULLNAMES);

  // tasks + migration of old names
  const alias = {
    "Trinity": "Trinity Phishing mailbox",
    "EoG": "Hyatt EoG",
    "General Tasks": null // drop
  };
  let storedTasks = JSON.parse(localStorage.getItem("tasks"));
  if (!Array.isArray(storedTasks) || !storedTasks.length) {
    tasks = [...CANONICAL_NAMES];
  } else {
    tasks = storedTasks
      .map(t => (t in alias ? alias[t] : t))
      .filter(Boolean);
    // Ensure all canonical tasks exist
    tasks = Array.from(new Set([...tasks, ...CANONICAL_NAMES]));
  }

  // prod times: seed any missing canonical times
  prodTimes = JSON.parse(localStorage.getItem("prodTimes")) || {};
  CANONICAL_NAMES.forEach(n => {
    if (typeof prodTimes[n] !== "number") prodTimes[n] = CANONICAL_TIMES[n];
  });

  // present: default to all true if empty/undefined
  present = JSON.parse(localStorage.getItem("present")) || {};
  if (!Object.keys(present).length) {
    users.forEach(u => (present[u] = true));
  }

  // Persist the migrated data so next load is clean
  saveData();
}

// ------- LOADERS -------
function loadData() {
  loadSavedData();
  showUsers();
  showTasks();
  showAssignments();
}

// ------- BADGES -------
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
      <td>${typeof prodTimes[t] === "number" ? prodTimes[t] : ''}</td>
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

  // Show union of configured tasks + actually-assigned tasks
  const displayTasks = Array.from(new Set([...tasks, ...Object.keys(taskMap)]));

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
            displayTasks.map(t =>
              `<tr>
                <td>${t}</td>
                <td>${
                  (taskMap[t] && taskMap[t].users.length)
                    ? taskMap[t].users.map(username => getUserBadge(username)).join(' ')
                    : ''
                }</td>
                <td>${
                  taskMap[t] && taskMap[t].users.length
                    ? (taskMap[t].prod !== undefined ? taskMap[t].prod : (typeof prodTimes[t] === "number" ? prodTimes[t] : ''))
                    : (t === "Failed ARPs" ? "5 (per ARP)" : (typeof prodTimes[t] === "number" ? prodTimes[t] : ''))
                }</td>
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
  saveData();
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
      <input type="number" class="form-control" id="prod_${i}" value="${prodTimes[t] ?? ''}" min="0">
      <span class="input-group-text">min</span>`;
    cont.appendChild(row);
  });
});

window.saveUsersEdit = function () {
  let val = document.getElementById('editUsersInput').value.trim();
  users = val ? val.split('\n').map(x => x.trim()).filter(Boolean) : [];
  saveData();
  bootstrap.Modal.getInstance(document.getElementById('editUsersModal')).hide();
  loadData();
};
window.saveTasksEdit = function () {
  let val = document.getElementById('editTasksInput').value.trim();
  tasks = val ? val.split('\n').map(x => x.trim()).filter(Boolean) : [];
  saveData();
  bootstrap.Modal.getInstance(document.getElementById('editTasksModal')).hide();
  loadData();
};
window.saveProdEdit = function () {
  let inputs = document.querySelectorAll("#editProdContainer input[type='number']");
  prodTimes = {};
  tasks.forEach((t, i) => prodTimes[t] = parseInt(inputs[i].value) || 0);
  saveData();
  bootstrap.Modal.getInstance(document.getElementById('editProdModal')).hide();
  loadData();
};

// ------- ASSIGN & SHUFFLE BUTTON -------
function assignTasks() {
  const pres = Object.keys(present).filter(u => present[u]);
  assignments = {};
  let productivity = {};

  pres.forEach(u => {
    assignments[u] = [];
    productivity[u] = 0;
  });

  if (!pres.length) {
    showAssignments();
    return;
  }

  // helper: choose N lowest-prod users (tie-breaker = fewer tasks)
  function pickUsers(count, exclude = []) {
    return [...pres]
      .filter(u => !exclude.includes(u))
      .sort((a, b) =>
        productivity[a] - productivity[b] ||
        assignments[a].length - assignments[b].length
      )
      .slice(0, count);
  }

  // Call log audit + Phone -> same up to 5 users
  const callPhoneSlots = Math.min(5, pres.length);
  const callLogUsers = pickUsers(callPhoneSlots);
  callLogUsers.forEach(u => {
    assignments[u].push({ task: "Call log audit", prod: 30 });
    assignments[u].push({ task: "Phone", prod: 30 });
    productivity[u] += 60;
  });

  // Assign remaining tasks except Call log, Phone, Failed ARPs
  CANONICAL_TASKS.forEach(t => {
    if (["Call log audit", "Phone", "Failed ARPs"].includes(t.name)) return;
    const take = Math.min(t.max, pres.length);
    const chosen = pickUsers(take);
    chosen.forEach(u => {
      assignments[u].push({ task: t.name, prod: t.time });
      productivity[u] += t.time;
    });
  });

  // Failed ARPs: 2 users with least productivity (ARP time not counted)
  const arpUsers = pickUsers(Math.min(2, pres.length));
  arpUsers.forEach(u => {
    assignments[u].push({ task: "Failed ARPs", prod: "5 (per ARP)" });
  });

  showAssignments();
}
function shuffleTasks() { assignTasks(); }

window.onload = loadData;
