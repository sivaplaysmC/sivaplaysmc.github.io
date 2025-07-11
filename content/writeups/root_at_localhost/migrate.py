import os

files = os.listdir()
files.remove("_index.md")
files.remove("migrate.py")
files.remove("migrate.bash")
files = filter(os.path.isfile, files)

for file in files:
    dirname = file.strip(".md")
    imgdir = os.path.join(dirname, "images")
    os.mkdir(dirname)
    os.mkdir(imgdir)
    open(os.path.join(imgdir, ".gitkeep"), "w").close()
    os.rename(file, os.path.join(dirname, "index.md"))
