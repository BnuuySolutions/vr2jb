#include <algorithm>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

// TODO: make a common header
#pragma pack(push, 1)
struct PacketHeader {
  uint8_t magic;
  uint8_t type;
  uint16_t length;
};
#pragma pack(pop)

enum PacketType : uint8_t {
  PKT_TTY_IN = 1,
  PKT_TTY_OUT = 2,
  PKT_TTY_START = 3,
  PKT_TTY_STOP = 4,
  PKT_FILE_START = 10,
  PKT_FILE_DATA = 11,
  PKT_FILE_END = 12,
  PKT_FILE_ERR = 13,
  PKT_EXEC_CMD = 20,
  PKT_EXEC_OUT = 21,
  PKT_EXEC_ERR = 22,
  PKT_EXEC_EXIT = 23
};

#define PKT_MAGIC 0xA5
#define MAX_PAYLOAD_SIZE (4096 - sizeof(PacketHeader))
#define USB_DATA2_PATH "/dev/usb_data2"

bool keep_running = true;
bool connection_active = false;
pid_t shell_pid = -1;
pid_t exec_pid = -1;

int exec_stdout_fd = -1;
int exec_stderr_fd = -1;
int file_upload_fd = -1;

void debug_log(const char *fmt, ...) {
  FILE *f = fopen("/tmp/daemon_debug.log", "a");
  if (!f)
    return;
  va_list args;
  va_start(args, fmt);
  vfprintf(f, fmt, args);
  fprintf(f, "\n");
  va_end(args);
  fclose(f);
}

void sigint_handler(int signum) {
  keep_running = false;
  connection_active = false;
}

void send_packet(int usb_fd, uint8_t type, const uint8_t *payload,
                 uint16_t len) {
  PacketHeader hdr = {PKT_MAGIC, type, len};
  struct iovec iov[2];

  iov[0].iov_base = &hdr;
  iov[0].iov_len = sizeof(hdr);

  if (len > 0 && payload != NULL) {
    iov[1].iov_base = (void *)payload;
    iov[1].iov_len = len;
    writev(usb_fd, iov, 2);
  } else {
    writev(usb_fd, iov, 1);
  }
}

void secure_fds() {
  int null_fd = open("/dev/null", O_RDWR);
  if (null_fd < 0)
    return;
  for (int i = 0; i <= 2; ++i) {
    if (null_fd != i)
      dup2(null_fd, i);
  }
  if (null_fd > 2)
    close(null_fd);
}

void daemonize_and_reset() {
  pid_t pid = fork();
  if (pid > 0)
    exit(0);
  setsid();
  pid = fork();
  if (pid > 0)
    exit(0);
  umask(0);
  chdir("/");
  secure_fds();
}

int main() {
  daemonize_and_reset();
  signal(SIGINT, sigint_handler);
  signal(SIGCHLD, SIG_IGN);

  debug_log("vr2bridge starting...");

  const char *pty_chars = "0123456789abcdef";

  while (keep_running) {
    int usb_fd = open(USB_DATA2_PATH, O_RDWR);
    if (usb_fd < 0) {
      sleep(1);
      continue;
    }

    int pty_master_fd = -1;
    char slave_name[64] = {0};

    for (int i = 0; i < 16; i++) {
      char master_name[32];
      snprintf(master_name, sizeof(master_name), "/dev/ptyp%c", pty_chars[i]);
      pty_master_fd = open(master_name, O_RDWR | O_NOCTTY);
      if (pty_master_fd >= 0) {
        strncpy(slave_name, ptsname(pty_master_fd), sizeof(slave_name) - 1);
        break;
      }
    }

    if (pty_master_fd < 0) {
      close(usb_fd);
      sleep(1);
      continue;
    }

    connection_active = true;
    fd_set read_fds;
    uint8_t buffer[4096];

    while (connection_active && keep_running) {
      FD_ZERO(&read_fds);
      FD_SET(usb_fd, &read_fds);

      // Only listen to the PTY master if the shell is actively running
      int max_fd = usb_fd;
      if (shell_pid > 0) {
        FD_SET(pty_master_fd, &read_fds);
        max_fd = std::max(max_fd, pty_master_fd);
      }

      if (exec_stdout_fd != -1) {
        FD_SET(exec_stdout_fd, &read_fds);
        max_fd = std::max(max_fd, exec_stdout_fd);
      }
      if (exec_stderr_fd != -1) {
        FD_SET(exec_stderr_fd, &read_fds);
        max_fd = std::max(max_fd, exec_stderr_fd);
      }

      struct timeval tv = {0, 50000};
      int activity = select(max_fd + 1, &read_fds, NULL, NULL, &tv);
      if (activity < 0 && errno != EINTR)
        break;

      if (FD_ISSET(usb_fd, &read_fds)) {
        PacketHeader hdr;
        ssize_t bytes_read = read(usb_fd, &hdr, sizeof(hdr));

        if (bytes_read == sizeof(hdr) && hdr.magic == PKT_MAGIC) {
          ssize_t payload_read = 0;
          if (hdr.length > 0) {
            payload_read = read(usb_fd, buffer, hdr.length);
          }

          switch (hdr.type) {
          case PKT_TTY_IN:
            if (shell_pid > 0)
              write(pty_master_fd, buffer, payload_read);
            break;

          case PKT_TTY_START:
            if (shell_pid > 0) {
              kill(shell_pid, SIGKILL);
              waitpid(shell_pid, NULL, WNOHANG);
            }
            buffer[payload_read] = '\0';
            shell_pid = fork();

            if (shell_pid == 0) {
              close(usb_fd);
              close(pty_master_fd);
              setsid();

              int pty_slave_fd = open(slave_name, O_RDWR | O_NOCTTY);
              ioctl(pty_slave_fd, TIOCSCTTY, 1);
              setpgid(0, 0);
              tcsetpgrp(pty_slave_fd, getpgrp());

              struct termios tios;
              tcgetattr(pty_slave_fd, &tios);
              cfmakeraw(&tios);
              tios.c_lflag |= (ISIG | ECHO | ICANON | IEXTEN);
              tios.c_iflag |= (ICRNL | IXON);
              tios.c_oflag |= (OPOST | ONLCR);
              tios.c_cc[VINTR] = 3;
              tios.c_cc[VQUIT] = 28;
              tios.c_cc[VEOF] = 4;
              tios.c_cc[VERASE] = 127;
              tcsetattr(pty_slave_fd, TCSANOW, &tios);

              dup2(pty_slave_fd, STDIN_FILENO);
              dup2(pty_slave_fd, STDOUT_FILENO);
              dup2(pty_slave_fd, STDERR_FILENO);

              setenv("TERM", "xterm", 1);
              setenv("PS1", "\\u@\\h:\\w\\$ ", 1);

              const char *shell_cmd =
                  (payload_read > 0) ? (char *)buffer : "sh";
              execl("/bin/sh", "sh", "-c", shell_cmd, NULL);
              exit(1);
            }
            break;

          case PKT_TTY_STOP:
            if (shell_pid > 0) {
              kill(shell_pid, SIGKILL);
              waitpid(shell_pid, NULL, WNOHANG);
              shell_pid = -1;
            }
            break;

          case PKT_FILE_START:
            buffer[payload_read] = '\0';
            file_upload_fd =
                open((char *)buffer, O_WRONLY | O_CREAT | O_TRUNC, 0755);
            break;

          case PKT_FILE_DATA:
            if (file_upload_fd != -1)
              write(file_upload_fd, buffer, payload_read);
            break;

          case PKT_FILE_END:
            if (file_upload_fd != -1) {
              close(file_upload_fd);
              file_upload_fd = -1;
            }
            break;

          case PKT_EXEC_CMD: {
            buffer[payload_read] = '\0';
            int pipe_out[2], pipe_err[2];
            if (pipe(pipe_out) == 0 && pipe(pipe_err) == 0) {
              exec_pid = fork();
              if (exec_pid == 0) {
                dup2(pipe_out[1], STDOUT_FILENO);
                dup2(pipe_err[1], STDERR_FILENO);
                close(pipe_out[0]);
                close(pipe_out[1]);
                close(pipe_err[0]);
                close(pipe_err[1]);
                execl("/bin/sh", "sh", "-c", (char *)buffer, NULL);
                exit(1);
              } else {
                close(pipe_out[1]);
                close(pipe_err[1]);
                exec_stdout_fd = pipe_out[0];
                exec_stderr_fd = pipe_err[0];
                fcntl(exec_stdout_fd, F_SETFL, O_NONBLOCK);
                fcntl(exec_stderr_fd, F_SETFL, O_NONBLOCK);
              }
            }
            break;
          }
          }
        } else if (bytes_read <= 0) {
          connection_active = false;
        }
      }

      if (shell_pid > 0 && FD_ISSET(pty_master_fd, &read_fds)) {
        ssize_t n = read(pty_master_fd, buffer, MAX_PAYLOAD_SIZE);
        if (n > 0)
          send_packet(usb_fd, PKT_TTY_OUT, buffer, n);
      }

      bool out_active = (exec_stdout_fd != -1);
      bool err_active = (exec_stderr_fd != -1);

      if (out_active && FD_ISSET(exec_stdout_fd, &read_fds)) {
        ssize_t n = read(exec_stdout_fd, buffer, MAX_PAYLOAD_SIZE);
        if (n > 0)
          send_packet(usb_fd, PKT_EXEC_OUT, buffer, n);
        else {
          close(exec_stdout_fd);
          exec_stdout_fd = -1;
          out_active = false;
        }
      }
      if (err_active && FD_ISSET(exec_stderr_fd, &read_fds)) {
        ssize_t n = read(exec_stderr_fd, buffer, MAX_PAYLOAD_SIZE);
        if (n > 0)
          send_packet(usb_fd, PKT_EXEC_ERR, buffer, n);
        else {
          close(exec_stderr_fd);
          exec_stderr_fd = -1;
          err_active = false;
        }
      }

      if (!out_active && !err_active && exec_pid > 0) {
        send_packet(usb_fd, PKT_EXEC_EXIT, NULL, 0);
        waitpid(exec_pid, NULL, WNOHANG);
        exec_pid = -1;
      }
    }

    close(pty_master_fd);
    close(usb_fd);
    if (shell_pid > 0) {
      kill(shell_pid, SIGKILL);
      waitpid(shell_pid, NULL, WNOHANG);
      shell_pid = -1;
    }
  }
  return 0;
}
