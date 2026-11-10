// Phase 1: light client-side convenience only. Real validation happens on the server.
document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("domain-input");
  if (input) {
    input.addEventListener("blur", () => {
      input.value = input.value.trim().toLowerCase();
    });
  }
});