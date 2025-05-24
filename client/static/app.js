const qid = (id) => document.getElementById(id);

let profilePicBase64 = localStorage.getItem("profilePic") || "";
const notifiedMessageSet = new Set(JSON.parse(localStorage.getItem("notifiedMessages") || "[]"));
let mediaRecorder = null;
let audioChunks = [];
let recordingStartTime = null;
let recordingTimerInterval = null;

const getStoredMessages = () =>
  JSON.parse(localStorage.getItem("cachedMessages") || "[]");

const storeMessages = (messages) => {
  localStorage.setItem("cachedMessages", JSON.stringify(messages));
};

const hashMessage = (message) => message.replace(/<[^>]*>/g, "").trim();

const showNotification = (message) => {
  const messageHash = hashMessage(message);
  if (!notifiedMessageSet.has(messageHash) && Notification.permission === "granted") {
    new Notification("New Message", { body: messageHash });
    notifiedMessageSet.add(messageHash);
    localStorage.setItem("notifiedMessages", JSON.stringify(Array.from(notifiedMessageSet)));
  }
};

const requestNotificationPermission = () => {
  if (Notification.permission !== "granted") {
    Notification.requestPermission();
  }
};

const handleProfilePicChange = (event) => {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onloadend = () => {
    profilePicBase64 = reader.result;
    localStorage.setItem("profilePic", profilePicBase64);
  };
  reader.readAsDataURL(file);
};

function handleWallpaperChange(event) {
  const file = event.target.files[0];
  if (!file || !file.type.startsWith('image/')) return;

  const reader = new FileReader();
  reader.onload = function (e) {
    const imageUrl = e.target.result;
    document.body.style.backgroundImage = `url(${imageUrl})`;
    localStorage.setItem('customWallpaper', imageUrl);
  };
  reader.readAsDataURL(file);
}

document.addEventListener('DOMContentLoaded', () => {
  const savedWallpaper = localStorage.getItem('customWallpaper');
  if (savedWallpaper) {
    document.body.style.backgroundImage = `url(${savedWallpaper})`;
  }
});

const handleMediaChange = (event) => {
  const file = event.target.files[0];
  if (!file) return;

  const reader = new FileReader();
  reader.onloadend = async () => {
    const mediaBase64 = DOMPurify.sanitize(reader.result);
    const message = `<pfp>${profilePicBase64}</pfp><media>${mediaBase64}</media>`;
    await fetch("/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message }),
    });
    fetchMessages();
  };
  reader.readAsDataURL(file);
};

const fetchMessages = async () => {
  try {
    const res = await fetch("/messages");
    const newMessages = await res.json();
    const storedMessages = getStoredMessages();

    const combinedMessages = [...storedMessages];
    newMessages.forEach((msg) => {
      if (!storedMessages.includes(msg)) {
        combinedMessages.push(msg);
      }
    });

    storeMessages(combinedMessages);
    renderMessages(combinedMessages);
  } catch (error) {
    console.warn("Fetch failed, loading from local cache.");
    renderMessages(getStoredMessages());
  }
};

const renderMessages = (messages) => {
  const messagesDiv = qid("messages");

  const base64Img = /^data:image\/(png|jpeg|jpg|gif|svg\+xml);base64,/;
  const base64Vid = /^data:video\/(mp4|webm|ogg);base64,/;
  const base64Audio = /^data:audio\/(webm|ogg);base64,/;

  const messagesHTML = messages
    .map((msg) => {
      const pfpMatch = msg.match(/<pfp>(.*?)<\/pfp>/);
      const mediaMatch = msg.match(/<media>(.*?)<\/media>/);
      const audioMatch = msg.match(/<audio>(.*?)<\/audio>/);

      const messageTextRaw = msg
        .replace(/<pfp>.*?<\/pfp>/, "")
        .replace(/<media>.*?<\/media>/, "")
        .replace(/<audio>.*?<\/audio>/, "")
        .trim();

      const messageText = DOMPurify.sanitize(messageTextRaw);

      const profilePicSrc =
        pfpMatch && base64Img.test(pfpMatch[1])
          ? DOMPurify.sanitize(pfpMatch[1])
          : "/static/default_pfp.jpg";

      const profilePic = `<img src="${profilePicSrc}" class="profile-pic" alt="Profile Picture" />`;

      let media = "";
      if (mediaMatch) {
        const src = DOMPurify.sanitize(mediaMatch[1]);
        if (base64Img.test(src)) {
          media = `<img src="${src}" class="media-img" alt="Media" onclick="openMediaModal('${src}', false)" />`;
        } else if (base64Vid.test(src)) {
          media = `<video class="media-video" controls onclick="openMediaModal('${src}', true)"><source src="${src}" type="video/mp4" />Your browser does not support video.</video>`;
        }
      }

      if (audioMatch) {
        const src = DOMPurify.sanitize(audioMatch[1]);
        media = `<audio controls class="media-audio"><source src="${src}" type="audio/webm" />Your browser does not support the audio element.</audio>`;
      }

      showNotification(messageText || "New media message");

      return `
        <div class="message-row">
          ${profilePic}
          <div class="message-bubble">
            ${messageText ? `<p>${messageText}</p>` : ""}
            ${media}
          </div>
        </div>`;
    })
    .join("");

  messagesDiv.innerHTML = DOMPurify.sanitize(messagesHTML, {
    SAFE_FOR_JQUERY: true,
    ADD_ATTR: ["onclick"],
  });

  messagesDiv.scrollTo({ top: messagesDiv.scrollHeight, behavior: "smooth" });
};

const sendMessage = async () => {
  const input = qid("messageInput");
  const msg = input.value.trim();
  if (!msg) return;

  const sanitizedMsg = DOMPurify.sanitize(msg, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
  const message = `<pfp>${profilePicBase64}</pfp>${sanitizedMsg}`;

  await fetch("/send", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message }),
  });

  input.value = "";
  fetchMessages();
};

const clearCache = () => {
  localStorage.removeItem("profilePic");
  localStorage.removeItem("notifiedMessages");
  localStorage.removeItem("cachedMessages");
  localStorage.removeItem("customWallpaper");

  profilePicBase64 = "";
  notifiedMessageSet.clear();
  audioChunks = [];
  recordingStartTime = null;
  clearInterval(recordingTimerInterval);
  recordingTimerInterval = null;

  qid("messages").innerHTML = "";
  qid("messageInput").value = "";
  document.body.style.backgroundImage = "";

  const micBtn = qid("micButton");
  micBtn.innerText = "🎤";
  micBtn.onclick = startVoiceRecording;

  hideRecordingStatus();
  qid("recordingTime").textContent = "00:00";
};

const toggleSettings = () => {
  qid("settings").classList.toggle("active");
};

const closeSettings = () => {
  qid("settings").classList.remove("active");
};

const toggleTheme = () => {
  document.body.classList.toggle("light-theme");
};

const openMediaModal = (src, isVideo = false) => {
  const modal = qid("mediaModal");
  modal.innerHTML = `<span class="close-btn" onclick="closeMediaModal(); event.stopPropagation();">&times;</span>`;

  if (isVideo) {
    const video = document.createElement("video");
    video.controls = true;
    video.src = src;
    video.autoplay = true;
    Object.assign(video.style, { maxWidth: "90%", maxHeight: "90%", borderRadius: "10px" });
    modal.appendChild(video);
  } else {
    const img = document.createElement("img");
    img.src = src;
    Object.assign(img.style, { maxWidth: "90%", maxHeight: "90%", borderRadius: "10px" });
    modal.appendChild(img);
  }

  modal.classList.add("active");
};

const closeMediaModal = () => {
  const modal = qid("mediaModal");
  modal.classList.remove("active");
  modal.innerHTML = `<span class="close-btn" onclick="closeMediaModal(); event.stopPropagation();">&times;</span>`;
};

const showRecordingStatus = () => {
  const el = qid("recordingStatus");
  el.classList.remove("hidden");
  setTimeout(() => el.classList.add("show"), 10);
};

const hideRecordingStatus = () => {
  const el = qid("recordingStatus");
  el.classList.remove("show");
  setTimeout(() => el.classList.add("hidden"), 300);
};

const startVoiceRecording = () => {
  navigator.mediaDevices
    .getUserMedia({ audio: true })
    .then((stream) => {
      mediaRecorder = new MediaRecorder(stream);
      audioChunks = [];
      recordingStartTime = Date.now();

      mediaRecorder.ondataavailable = (event) => audioChunks.push(event.data);

      mediaRecorder.onstop = async () => {
        clearInterval(recordingTimerInterval);
        hideRecordingStatus();

        if (!audioChunks.length) return;

        const audioBlob = new Blob(audioChunks, { type: "audio/webm" });
        const reader = new FileReader();
        reader.onloadend = async () => {
          const audioBase64 = DOMPurify.sanitize(reader.result);
          const message = `<pfp>${profilePicBase64}</pfp><audio>${audioBase64}</audio>`;
          await fetch("/send", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message }),
          });
          fetchMessages();
        };
        reader.readAsDataURL(audioBlob);
      };

      mediaRecorder.start();
      startTimer();

      const micBtn = qid("micButton");
      micBtn.innerText = "⏹️";
      micBtn.onclick = stopVoiceRecording;

      showRecordingStatus();
    })
    .catch((err) => {
      alert("Microphone access denied.");
      console.error(err);
    });
};

const stopVoiceRecording = () => {
  if (mediaRecorder && mediaRecorder.state === "recording") {
    mediaRecorder.stop();
  }
  const micBtn = qid("micButton");
  micBtn.innerText = "🎤";
  micBtn.onclick = startVoiceRecording;
};

const cancelVoiceRecording = () => {
  if (mediaRecorder && mediaRecorder.state !== "inactive") {
    mediaRecorder.stop();
  }
  audioChunks = [];
  clearInterval(recordingTimerInterval);
  hideRecordingStatus();

  const micBtn = qid("micButton");
  micBtn.innerText = "🎤";
  micBtn.onclick = startVoiceRecording;
};

const startTimer = () => {
  const timerElement = qid("recordingTime");
  recordingTimerInterval = setInterval(() => {
    const elapsed = Math.floor((Date.now() - recordingStartTime) / 1000);
    const minutes = String(Math.floor(elapsed / 60)).padStart(2, "0");
    const seconds = String(elapsed % 60).padStart(2, "0");

    timerElement.textContent = `${minutes}:${seconds}`;

    if (elapsed >= 60) {
      cancelVoiceRecording();
    }
  }, 1000);
};

const isAudioPlaying = () => {
  return Array.from(document.querySelectorAll("audio")).some(
    (audio) => !audio.paused && !audio.ended
  );
};

document.addEventListener("DOMContentLoaded", () => {
  const savedPic = localStorage.getItem("profilePic");
  if (savedPic) {
    profilePicBase64 = savedPic;
  }

  qid("messageInput").addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      sendMessage();
    }
  });

  qid("recordingStatus").querySelector(".cancel-button").onclick = cancelVoiceRecording;

  requestNotificationPermission();
  renderMessages(getStoredMessages());
  fetchMessages();

  setInterval(() => {
    if (!isAudioPlaying()) {
      fetchMessages();
    }
  }, 3000);
});

window.addEventListener("unload", () => {
  localStorage.removeItem("cachedMessages");
  localStorage.removeItem("notifiedMessages");
});