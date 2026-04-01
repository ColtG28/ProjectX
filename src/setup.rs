use std::process::Command;

pub fn ensure_docker() {
    if is_docker_running() {
        println!("Docker is already running.");
        return;
    }

    if is_docker_installed() {
        println!("Docker is installed but not running, starting it...");
        start_docker();
        return;
    }

    println!("Docker not found, installing...");
    install_docker();
}

fn is_docker_running() -> bool {
    Command::new("docker")
        .arg("info")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn is_docker_installed() -> bool {
    #[cfg(target_os = "macos")]
    {
        Command::new("colima")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[cfg(target_os = "linux")]
    {
        Command::new("docker")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[cfg(target_os = "windows")]
    {
        // Check if WSL2 and docker are available
        Command::new("wsl")
            .args(["--list", "--running"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }
}

fn start_docker() {
    #[cfg(target_os = "macos")]
    {
        println!("Starting Colima...");
        Command::new("colima")
            .arg("start")
            .status()
            .expect("Failed to start Colima");

        wait_for_docker();
    }

    #[cfg(target_os = "linux")]
    {
        println!("Starting Docker service...");
        Command::new("sudo")
            .args(["systemctl", "start", "docker"])
            .status()
            .expect("Failed to start Docker service");

        wait_for_docker();
    }

    #[cfg(target_os = "windows")]
    {
        println!("Starting Docker in WSL2...");
        Command::new("wsl")
            .args(["-e", "sudo", "service", "docker", "start"])
            .status()
            .expect("Failed to start Docker in WSL2");

        wait_for_docker();
    }
}

fn install_docker() {
    #[cfg(target_os = "macos")]
    {
        // Install Homebrew if missing
        if !is_brew_installed() {
            println!("Installing Homebrew...");
            Command::new("bash")
                .args(["-c", "/bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""])
                .status()
                .expect("Failed to install Homebrew");
        }

        println!("Installing Colima and Docker CLI...");
        Command::new("brew")
            .args(["install", "colima", "docker"])
            .status()
            .expect("Failed to install Colima and Docker");

        start_docker();
    }

    #[cfg(target_os = "linux")]
    {
        println!("Installing Docker Engine...");
        Command::new("bash")
            .args(["-c", "curl -fsSL https://get.docker.com | sh"])
            .status()
            .expect("Failed to install Docker");

        // Add current user to docker group to avoid needing sudo every time
        let user = std::env::var("USER").unwrap_or_default();
        Command::new("sudo")
            .args(["usermod", "-aG", "docker", &user])
            .status()
            .expect("Failed to add user to docker group");

        start_docker();
    }

    #[cfg(target_os = "windows")]
    {
        // Enable WSL2 if not already enabled
        println!("Enabling WSL2...");
        Command::new("powershell")
            .args(["-Command", "wsl --install --no-distribution"])
            .status()
            .expect("Failed to enable WSL2");

        // Install Ubuntu in WSL2
        println!("Installing Ubuntu in WSL2...");
        Command::new("powershell")
            .args(["-Command", "wsl --install -d Ubuntu"])
            .status()
            .expect("Failed to install Ubuntu in WSL2");

        // Install Docker Engine inside WSL2
        println!("Installing Docker Engine inside WSL2...");
        Command::new("wsl")
            .args(["-e", "bash", "-c", "curl -fsSL https://get.docker.com | sh"])
            .status()
            .expect("Failed to install Docker in WSL2");

        // Add wsl user to docker group
        Command::new("wsl")
            .args(["-e", "bash", "-c", "sudo usermod -aG docker $USER"])
            .status()
            .expect("Failed to add user to docker group in WSL2");

        start_docker();
    }
}

fn wait_for_docker() {
    println!("Waiting for Docker to be ready...");
    for _ in 0..30 {
        std::thread::sleep(std::time::Duration::from_secs(2));
        if is_docker_running() {
            println!("Docker is ready.");
            return;
        }
    }
    eprintln!("Docker took too long to start, please try again.");
    std::process::exit(1);
}

#[cfg(target_os = "macos")]
fn is_brew_installed() -> bool {
    Command::new("brew")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn ensure_ubuntu_image() {
    println!("Checking for Ubuntu image...");
    let output = Command::new("docker")
        .args(["image", "inspect", "ubuntu:22.04"])
        .output()
        .expect("Failed to run docker");

    if !output.status.success() {
        println!("Pulling ubuntu:22.04...");
        Command::new("docker")
            .args(["pull", "ubuntu:22.04"])
            .status()
            .expect("Failed to pull Ubuntu image");
    } else {
        println!("Ubuntu image already present.");
    }
}