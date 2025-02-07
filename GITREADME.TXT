1. 安装 Git
使用系统自带的包管理器 dnf 安装:
sudo dnf install git

验证安装:
git --version

2. 配置 Git
配置用户信息，这是 Git 操作所需的基础信息
git config --global user.name "你的名字"
git config --global user.email "你的邮箱"

验证配置:
git config --list

3. 创建本地 Git 仓库
选择一个目录用于存储项目:
mkdir my_project
cd my_project

初始化 Git 仓库:
git init

执行后，目录下会生成一个 .git 隐藏文件夹，表示该目录已被 Git 管理

4. 添加文件到 Git 仓库
创建文件:
echo "Hello Git" > readme.md

添加文件到暂存区:
git add readme.md

提交到本地仓库:
git commit -m "首次提交"

4.1 添加当前目录及所有子目录的内容
如果你当前所在目录是项目的根目录:
git add .
. 的作用：表示当前目录下的所有内容，包括子目录中的文件
所有新增、修改的文件都会被添加到暂存区

4.2 添加特定目录
如果你只想添加某个特定的目录，例如 my_folder
git add my_folder
这将递归地添加 my_folder 及其子目录下的所有文件


5. 查看仓库状态
git status

6. 检查提交历史
git log

7. 本地仓库操作示例
git branch my_branch

切换到新分支:
git checkout my_branch

合并分支:
git merge my_branch

删除分支:
git branch -d my_branch

8. 配置 Git 仓库的忽略文件
创建 .gitignore 文件来忽略不需要被版本控制的文件或文件夹，例如:

# 忽略所有 .log 文件
*.log

# 忽略 node_modules 文件夹
node_modules/


/*----------------------------------------------------------------------*/

# 提交代码时遇到的问题

ERRMSG：
{
    git add trace.h 
    error: insufficient permission for adding an object to repository database .git/objects
    error: trace.h: failed to insert into database
    error: unable to index file 'trace.h'
    fatal: updating files failed
}

Solution
{
    1. 检查 .git 目录的权限
    首先，检查 .git 目录及其子目录的权限。Git 会将对象存储在 .git/objects 目录中，如果该目录的权限设置不正确，Git 就无法写入。

    你可以运行以下命令来检查并修复权限问题：ls -lR .git/objects

    如果你看到 objects 目录或其中的文件没有写权限，使用 chmod 命令调整权限：chmod -R u+rw .git/

    如果你需要更强的权限设置，可以使用：su; chown -R $(whoami):$(whoami) .git/
}


/*----------------------------------------------------------------------*/

# 1. 设置 core 文件大小无限制
ulimit -c unlimited

# 2. 配置 core 文件存储路径
echo "kernel.core_pattern=/tmp/core.%e.%p" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# 3. 触发段错误并生成 core dump
./crash

# 4. 查看生成的 core 文件
ls /tmp/core.*

/*----------------------------------------------------------------------*/

