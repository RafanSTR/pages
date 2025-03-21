document.addEventListener("DOMContentLoaded", () => {
  const fileInput = document.getElementById("file-input");
  const uploadButton = document.getElementById("upload-button");
  const uploadText = document.getElementById("upload-text");
  const errorMessage = document.getElementById("error-message");
  const errorText = errorMessage.querySelector("p");
  const successMessage = document.getElementById("success-message");
  const downloadLink = document.getElementById("download-link");
  const copyButton = document.getElementById("copy-button");
  const progressContainer = document.getElementById("progress-container");
  const progressBar = document.getElementById("progress-bar");
  const progressText = document.getElementById("progress-text");

  function showError(msg) {
    errorMessage.style.display = "flex";
    errorText.textContent = msg;
  }

  function showSuccess(link) {
    errorMessage.style.display = "none"; // Sembunyikan error jika ada
    successMessage.style.display = "flex";
    downloadLink.href = link;
    downloadLink.textContent = link;
  }

  function resetUI() {
    successMessage.style.display = "none";
    errorMessage.style.display = "none";
    progressContainer.style.display = "none";
    progressBar.style.width = "0%";
    progressText.textContent = "0%";
    downloadLink.textContent = ""; // Hapus link saat reset
    downloadLink.href = "#";
  }

  // Saat memilih file baru, reset tampilan
  fileInput.addEventListener("change", () => {
    resetUI();
  });

  uploadButton.addEventListener("click", () => {
    const file = fileInput.files[0];
    if (!file) {
      showError("Please select a file.");
      return;
    }

    if (file.size > 20 * 1024 * 1024) {
      showError("File size exceeds 20MB limit.");
      return;
    }

    resetUI();
    progressContainer.style.display = "block";

    const formData = new FormData();
    formData.append("file", file);

    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/upload", true);

    xhr.upload.onprogress = (event) => {
      if (event.lengthComputable) {
        const percent = Math.round((event.loaded / event.total) * 100);
        progressBar.style.width = percent + "%";
        progressText.textContent = percent + "%";
      }
    };

    xhr.onload = () => {
      progressBar.style.width = "100%";
      progressText.textContent = "100%";

      if (xhr.status === 200) {
        const response = JSON.parse(xhr.responseText);
        showSuccess(response.download);
      } else {
        showError("Upload failed.");
      }
    };

    xhr.onerror = () => {
      showError("Network error.");
    };

    xhr.send(formData);
  });

  // Tombol copy link ke clipboard
  copyButton.addEventListener("click", () => {
    if (downloadLink.textContent) {
      navigator.clipboard.writeText(downloadLink.textContent).then(() => {
        alert("Link copied to clipboard!");
      });
    }
  });
});

