document.addEventListener("DOMContentLoaded", () => {
    // Enhanced fade animation with scaling
    const containers = document.querySelectorAll(".container");
    containers.forEach((container, index) => {
        container.style.opacity = 0;
        container.style.transform = "scale(0.95) translateY(20px)";
        
        setTimeout(() => {
            container.style.transition = "opacity 0.8s ease, transform 0.8s ease";
            container.style.opacity = 1;
            container.style.transform = "scale(1) translateY(0)";
        }, index * 200);
    });

    // Input focus animations
    document.querySelectorAll('input').forEach(input => {
        input.addEventListener('focus', (e) => {
            e.target.parentElement.style.transform = "scale(1.02)";
        });
        input.addEventListener('blur', (e) => {
            e.target.parentElement.style.transform = "scale(1)";
        });
    });
});