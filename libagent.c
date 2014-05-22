
ssize_t read_fd(int fd, int *recvfd)
{
        char c, buff[CMSG_SPACE(sizeof(int))];

    struct msghdr msg;
    struct iovec iov[1];

    memset(&msg,   0, sizeof(msg));
    memset(iov,    0, sizeof(iov));

        msg.msg_control = buff;
        msg.msg_controllen = sizeof buff;

    iov[0].iov_base = &c;
        iov[0].iov_len = 1;

        msg.msg_iov = iov;
        msg.msg_iovlen = 1;


    ssize_t n = recvmsg(fd, &msg, 0);

    if (n <= 0) {
        logger(LOG_ERR, "read_fd: recvmsg returned %d: %s\n", n, strerror(errno));
        return n;
    }

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);

    if (cmsg != NULL && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {

        int *cdata = (int*) CMSG_DATA(cmsg);

        *recvfd = *cdata;

        return n;

    } else {
        logger(LOG_ERR, "read_fd: recvmsg no fd %d\n", n);

        *recvfd = -1;
    }


    return n;
}

size_t write_fd(int fd, int sendfd)
{
    struct msghdr msg = {0};
    struct cmsghdr *cmsg;

    char buff[CMSG_SPACE(sizeof(int))];

    msg.msg_control = buff;
    msg.msg_controllen = sizeof buff;

    cmsg = CMSG_FIRSTHDR(&msg);

    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));

    int *cdata = (int *) CMSG_DATA(cmsg);
    memcpy(cdata, &sendfd, sizeof(int));

    msg.msg_controllen = cmsg->cmsg_len;

    struct iovec iov[1];

        iov[0].iov_base = (void*)"";
        iov[0].iov_len = 1;
        msg.msg_iov = iov;
        msg.msg_iovlen = 1;

    int ret = sendmsg(fd, &msg, 0);
    if (ret != 1) {
        logger(LOG_ERR, "write_fd: sendmsg returned with %d\n", ret);
    }

    return ret;
}

