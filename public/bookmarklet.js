// Builds the bookmarklet for this site's own address: it opens /scan with the current page.
const scanBase = `${window.location.origin}/scan?url=`;
const code = `javascript:(()=>{window.open(${JSON.stringify(scanBase)}+encodeURIComponent(location.href),"_blank","noopener")})()`;
document.querySelector("#bookmarklet-link").href = code;
document.querySelector("#bookmarklet-code").value = code;
document.querySelector("#search-template").textContent = `${scanBase}%s`;
document.querySelector("#bookmarklet-link").addEventListener("click", (event) => {
  event.preventDefault();
  window.alert("Drag this button to your bookmarks bar instead of clicking it.");
});
