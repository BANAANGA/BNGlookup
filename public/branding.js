async function applySiteBranding() {
  try {
    const response = await fetch("/api/branding", { credentials: "same-origin" });
    if (!response.ok) throw new Error("Unable to load site branding.");
    const branding = await response.json();
    const title = typeof branding.title === "string" ? branding.title : "";
    if (!title) return;

    document.querySelectorAll(".brand-name").forEach((element) => {
      element.textContent = title;
    });

    const titleSeparator = document.title.indexOf(" · ");
    document.title = titleSeparator === -1
      ? title
      : `${document.title.slice(0, titleSeparator)} · ${title}`;

    const logoUrl = typeof branding.logoUrl === "string" && branding.logoUrl ? branding.logoUrl : branding.iconUrl;
    if (typeof logoUrl === "string" && logoUrl) {
      document.querySelectorAll(".brand-logo").forEach((element) => {
        element.src = logoUrl;
      });
    }
    if (typeof branding.iconUrl === "string" && branding.iconUrl) {
      document.querySelectorAll('link[rel="icon"]').forEach((element) => {
        element.href = branding.iconUrl;
        element.type = branding.iconUrl.startsWith("data:image/")
          ? branding.iconUrl.slice(5, branding.iconUrl.indexOf(";"))
          : "";
      });
    }
  } catch (error) {
    console.error("Site branding could not be applied:", error);
  }
}

window.applySiteBranding = applySiteBranding;
applySiteBranding();
