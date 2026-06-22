#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

static const char *source = "/dev/loop1";
static const char *target = "/mnt/lmi-diag-root";
static const char *tmp_target = "/mnt/lmi-tmpfs-probe";
static const char *bind_target = "/tmp/lmi-bdev-bind";
static const char *filesystem = "ext4";
static const char *mount_data = "noload";

static int probe_mount(const char *name, const char *mount_source,
		       const char *filesystem, unsigned long flags,
		       const char *data, const char *mount_target)
{
	if (mount(mount_source, mount_target, filesystem, flags, data) == 0) {
		printf("%s_mount=ok\n", name);
		if (umount2(mount_target, 0) != 0) {
			printf("%s_umount=failed errno=%d message=%s\n", name,
			       errno, strerror(errno));
			return 1;
		}
		printf("%s_umount=ok\n", name);
		return 0;
	}
	printf("%s_mount=failed errno=%d message=%s\n", name, errno,
	       strerror(errno));
	return 1;
}

int main(int argc, char **argv)
{
	struct stat st;
	int fd;

	if (argc == 2 && strcmp(argv[1], "umount") == 0) {
		if (umount2(target, 0) == 0) {
			puts("umount2=ok");
			return 0;
		}
		printf("umount2=failed errno=%d message=%s\n", errno,
		       strerror(errno));
		return 1;
	}
	if (argc == 2)
		source = argv[1];
	if (argc == 3) {
		source = argv[1];
		filesystem = argv[2];
		mount_data = strcmp(filesystem, "ext4") == 0 ? "noload" : "";
	}

	if (stat(source, &st) != 0) {
		printf("source_stat=failed errno=%d message=%s\n", errno,
		       strerror(errno));
		return 1;
	}
	printf("source_rdev=%u:%u\n", major(st.st_rdev), minor(st.st_rdev));

	fd = open(source, O_RDONLY);
	if (fd < 0) {
		printf("source_open=failed errno=%d message=%s\n", errno,
		       strerror(errno));
		return 1;
	}
	close(fd);
	if (stat(target, &st) != 0) {
		printf("target_stat=failed errno=%d message=%s\n", errno,
		       strerror(errno));
		return 1;
	}
	printf("target_mode=%o\n", st.st_mode & 07777);

	if (mkdir(tmp_target, 0755) != 0 && errno != EEXIST) {
		printf("tmp_target_mkdir=failed errno=%d message=%s\n", errno,
		       strerror(errno));
		return 1;
	}
	probe_mount("tmpfs", "none", "tmpfs", MS_RDONLY, "size=4096",
		    tmp_target);
	probe_mount("pmos_boot", "/dev/loop0p1", "ext2", MS_RDONLY, "",
		    target);
	probe_mount("pmos_root_partition", "/dev/loop0p2", "ext4", MS_RDONLY,
		    "noload", target);

	fd = open(bind_target, O_CREAT | O_RDONLY, 0600);
	if (fd < 0) {
		printf("bind_target_open=failed errno=%d message=%s\n", errno,
		       strerror(errno));
	} else {
		close(fd);
		if (mount(source, bind_target, NULL, MS_BIND, NULL) == 0) {
			puts("source_bind_mount=ok");
			if (umount2(bind_target, 0) == 0)
				puts("source_bind_umount=ok");
			else
				printf("source_bind_umount=failed errno=%d message=%s\n",
				       errno, strerror(errno));
		} else {
			printf("source_bind_mount=failed errno=%d message=%s\n",
			       errno, strerror(errno));
		}
	}

	if (mount(source, target, filesystem, MS_RDONLY, mount_data) == 0) {
		printf("mount2=ok filesystem=%s flags=MS_RDONLY data=%s\n",
		       filesystem, mount_data);
		return 0;
	}
	printf("mount2=failed errno=%d message=%s\n", errno, strerror(errno));
	return 1;
}
