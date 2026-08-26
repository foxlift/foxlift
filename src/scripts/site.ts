// ABOUTME: Reveals landing-page content as it enters the viewport.
// ABOUTME: Uses a browser-native observer and respects reduced-motion preferences.
document.documentElement.classList.add("js");

const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const revealItems = document.querySelectorAll<HTMLElement>("[data-reveal]");

if (reduceMotion || !("IntersectionObserver" in window)) {
  revealItems.forEach((item) => item.setAttribute("data-visible", ""));
} else {
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        entry.target.setAttribute("data-visible", "");
        observer.unobserve(entry.target);
      });
    },
    { rootMargin: "0px 0px -10%", threshold: 0.14 },
  );

  revealItems.forEach((item) => observer.observe(item));
}
