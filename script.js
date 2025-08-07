
let questions = [];
let current = 0;
let score = 0;
let startTime;
let studyMode = false;
let answered = [];
let savedKey = "linuxplus_quiz_state";

// Timer
function updateTimer() {
  const elapsed = Math.floor((Date.now() - startTime) / 1000);
  const mins = Math.floor(elapsed / 60);
  const secs = elapsed % 60;
  document.getElementById("timer").textContent = `${mins}m ${secs}s`;
  requestAnimationFrame(updateTimer);
}

// Start quiz
function startQuiz(num) {
  studyMode = document.getElementById("studyMode").checked;
  questions = shuffle([...allQuestions]).slice(0, num);
  current = 0;
  score = 0;
  answered = new Array(questions.length).fill(null);
  startTime = Date.now();
  showQuestion();
  document.getElementById("start-buttons").style.display = "none";
  document.getElementById("nav-buttons").style.display = "block";
  updateTimer();
  saveProgress();
}

// Show question
function showQuestion() {
  const q = questions[current];
  const choices = q.choices.map((c, i) =>
    `<label><input type="radio" name="choice" value="${"ABCD"[i]}" /> ${c}</label>`
  ).join('');
  document.getElementById("quiz-container").innerHTML = `
    <div class="question-box">
      <h3>${q.question}</h3>
      <div class="answers">${choices}</div>
    </div>
  `;
  document.getElementById("qNumber").textContent = current + 1;
  document.getElementById("qTotal").textContent = questions.length;
  document.getElementById("feedback").textContent = "";
  saveProgress();
}

// Navigation
function nextQuestion() {
  if (current < questions.length - 1) {
    current++;
    showQuestion();
  }
}
function prevQuestion() {
  if (current > 0) {
    current--;
    showQuestion();
  }
}

// Check answer
function checkAnswer() {
  const q = questions[current];
  const selected = document.querySelector('input[name="choice"]:checked');
  if (!selected) return alert("Select an answer.");
  const answer = selected.value;
  const correct = q.answer;
  if (answer === correct) {
    if (answered[current] !== true) {
      score++;
      answered[current] = true;
    }
    document.getElementById("feedback").textContent = "✅ Correct!";
  } else {
    answered[current] = false;
    document.getElementById("feedback").textContent = `❌ Wrong. Correct answer: ${correct}`;
  }
  document.getElementById("score").textContent = score;
  saveProgress();
}

// Dark mode
function toggleDark() {
  document.body.classList.toggle("dark-mode");
}

// Review screen
function finishQuiz() {
  document.getElementById("nav-buttons").style.display = "none";
  let html = "<h2>Review of Missed Questions</h2>";
  questions.forEach((q, i) => {
    if (answered[i] === false) {
      html += `<div class='question-box'><strong>Q${i + 1}:</strong> ${q.question}<br><em>Correct Answer:</em> ${q.choices["ABCD".indexOf(q.answer)]}</div>`;
    }
  });
  document.getElementById("review-section").innerHTML = html || "<p>✅ No missed questions!</p>";
  localStorage.removeItem(savedKey);
}

// Persistence
function saveProgress() {
  const state = { current, score, answered, questions, studyMode, startTime };
  localStorage.setItem(savedKey, JSON.stringify(state));
}
window.onload = () => {
  const saved = localStorage.getItem(savedKey);
  if (saved) {
    const state = JSON.parse(saved);
    questions = state.questions;
    current = state.current;
    score = state.score;
    answered = state.answered;
    studyMode = state.studyMode;
    startTime = state.startTime;
    document.getElementById("start-buttons").style.display = "none";
    document.getElementById("nav-buttons").style.display = "block";
    updateTimer();
    showQuestion();
  }
};

// Helper
function shuffle(array) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [array[i], array[j]] = [array[j], array[i]];
  }
  return array;
}
