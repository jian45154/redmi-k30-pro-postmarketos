# LMI CLI Installer v0.1.0-alpha.1

这是 Xiaomi Redmi K30 Pro / POCO F2 Pro (`lmi`) 的 Linux/WSL2 CLI
**仅验证源码预览**。

> 本版不是可刷机镜像：不含 boot/rootfs、profile 或设备写入入口。
> `install` 始终是不访问设备的 dry-run，CLI 只允许可选的 fastboot
> 只读查询。

完整下载、校验、命令边界和维护者说明见
[`docs/lmi-cli-installer.md`](docs/lmi-cli-installer.md)。

运行测试：

```sh
python3 -m unittest discover -s tests/lmi_installer -p 'test_*.py' -v
```

重建 GitHub Release 源码资产：

```sh
scripts/73_build_lmi_installer_source_release.sh /tmp/lmi-installer-release
```

许可证见 `LICENSE` 与 `NOTICE`。
