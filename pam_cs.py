import subprocess

def run_command(command):
    """Helper function to run shell commands."""
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result

def test_pam_auth_success():
    """Test PAM authentication with valid credentials."""
    run_command("sudo useradd testuser")
    run_command("echo 'testuser:password' | sudo chpasswd")
    result = run_command("echo 'password' | sudo pam_exec.so -v -- /bin/true testuser")
    if result.returncode == 0:
        print("Test 1: PAM Authentication (Success) - PASS")
    else:
        print("Test 1: PAM Authentication (Success) - FAIL")
    run_command("sudo userdel -r testuser")

def test_pam_auth_failure():
    """Test PAM authentication with invalid credentials."""
    run_command("sudo useradd testuser")
    run_command("echo 'testuser:password' | sudo chpasswd")
    result = run_command("echo 'wrongpassword' | sudo pam_exec.so -v -- /bin/true testuser")
    if result.returncode != 0:
        print("Test 2: PAM Authentication (Failure) - PASS")
    else:
        print("Test 2: PAM Authentication (Failure) - FAIL")
    run_command("sudo userdel -r testuser")

def test_pam_account_policy():
    """Test PAM account policy (e.g., password expiration)."""
    run_command("sudo useradd testuser")
    run_command("echo 'testuser:password' | sudo chpasswd")
    run_command("sudo chage -M 1 testuser")  # Set password to expire in 1 day
    result = run_command("sudo pam_exec.so -v -- /bin/true testuser")
    if result.returncode == 0:
        print("Test 3: PAM Account Policy - PASS")
    else:
        print("Test 3: PAM Account Policy - FAIL")
    run_command("sudo userdel -r testuser")

def test_pam_session_management():
    """Test PAM session management (e.g., session creation)."""
    run_command("sudo useradd testuser")
    run_command("echo 'testuser:password' | sudo chpasswd")
    result = run_command("sudo pam_exec.so -v -- /bin/true testuser")
    if result.returncode == 0:
        print("Test 4: PAM Session Management - PASS")
    else:
        print("Test 4: PAM Session Management - FAIL")
    run_command("sudo userdel -r testuser")

def test_pam_password_policy():
    """Test PAM password policy (e.g., password complexity)."""
    run_command("sudo useradd testuser")
    run_command("echo 'testuser:password' | sudo chpasswd")
    result = run_command("echo 'newpassword' | sudo pam_exec.so -v -- /bin/true testuser")
    if result.returncode == 0:
        print("Test 5: PAM Password Policy - PASS")
    else:
        print("Test 5: PAM Password Policy - FAIL")
    run_command("sudo userdel -r testuser")

def test_pam_limits():
    """Test PAM limits (e.g., resource limits for users)."""
    run_command("sudo useradd testuser")
    run_command("echo 'testuser:password' | sudo chpasswd")
    run_command("echo 'testuser hard nproc 100' | sudo tee -a /etc/security/limits.conf")
    result = run_command("sudo pam_exec.so -v -- /bin/true testuser")
    if result.returncode == 0:
        print("Test 6: PAM Limits - PASS")
    else:
        print("Test 6: PAM Limits - FAIL")
    run_command("sudo userdel -r testuser")
    run_command("sudo sed -i '/testuser hard nproc 100/d' /etc/security/limits.conf")

def test_pam_tally2():
    """Test PAM tally2 (e.g., account locking after failed attempts)."""
    run_command("sudo useradd testuser")
    run_command("echo 'testuser:password' | sudo chpasswd")
    for _ in range(3):
        run_command("echo 'wrongpassword' | sudo pam_exec.so -v -- /bin/true testuser")
    result = run_command("echo 'password' | sudo pam_exec.so -v -- /bin/true testuser")
    if result.returncode != 0:
        print("Test 7: PAM Tally2 (Account Locking) - PASS")
    else:
        print("Test 7: PAM Tally2 (Account Locking) - FAIL")
    run_command("sudo pam_tally2 --user=testuser --reset")
    run_command("sudo userdel -r testuser")

def test_pam_root_ok():
    """Test PAM root access (e.g., allow root without restrictions)."""
    result = run_command("sudo pam_exec.so -v -- /bin/true root")
    if result.returncode == 0:
        print("Test 8: PAM Root Access - PASS")
    else:
        print("Test 8: PAM Root Access - FAIL")

def test_pam_deny():
    """Test PAM deny module (e.g., explicitly deny access)."""
    run_command("sudo useradd testuser")
    run_command("echo 'testuser:password' | sudo chpasswd")
    run_command("echo 'auth required pam_deny.so' | sudo tee -a /etc/pam.d/common-auth")
    result = run_command("echo 'password' | sudo pam_exec.so -v -- /bin/true testuser")
    if result.returncode != 0:
        print("Test 9: PAM Deny Module - PASS")
    else:
        print("Test 9: PAM Deny Module - FAIL")
    run_command("sudo sed -i '/auth required pam_deny.so/d' /etc/pam.d/common-auth")
    run_command("sudo userdel -r testuser")

def test_pam_wheel():
    """Test PAM wheel group (e.g., restrict su to wheel group)."""
    run_command("sudo groupadd wheel")
    run_command("sudo useradd testuser")
    run_command("sudo usermod -aG wheel testuser")
    run_command("echo 'testuser:password' | sudo chpasswd")
    result = run_command("echo 'password' | sudo pam_exec.so -v -- /bin/true testuser")
    if result.returncode == 0:
        print("Test 10: PAM Wheel Group - PASS")
    else:
        print("Test 10: PAM Wheel Group - FAIL")
    run_command("sudo userdel -r testuser")
    run_command("sudo groupdel wheel")

if __name__ == "__main__":
    test_pam_auth_success()
    test_pam_auth_failure()
    test_pam_account_policy()
    test_pam_session_management()
    test_pam_password_policy()
    test_pam_limits()
    test_pam_tally2()
    test_pam_root_ok()
    test_pam_deny()
    test_pam_wheel()
