git submodule update --recursive --remote
git submodule foreach git pull origin HEAD
echo "Update submodules done"
cargo update
forge clean
forge build --force