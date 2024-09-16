# Google Cloud CLI create new Project
gcloud projects create vcid

# Google Cloud CLI list all Projects
gcloud projects list

# Google Cloud CLI select Project to Deploy VM in
gcloud config set project vcid-ID

# Google Cloud CLI enable compute modul
gcloud services enable compute.googleapis.com

# Terraform Initialize
terraform init

# Terraform Plan deployment from file main.tf (cli in same directory where main.tf is)
terraform plan

# Terraform create deployment from file main.tf (cli in same directory where main.tf is)
terraform apply

# Google Cloud CLI connect to created VM
gcloud compute ssh vcidvm

# VM Setup install Docker Components (Setup from Official Websit https://docs.docker.com/engine/install/debian/)
sudo apt-get update
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
# Add the repository to Apt sources:
echo   "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
$(. /etc/os-release && echo "$VERSION_CODENAME") stable" |   sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# VM Setup Create App Dir and access it
mkdir /VCID
cd /VCID

# VM Setup Clone App repository
git clone https://github.com/gigersam/VCID_Praxisarbeit_Public.git

# VM Setup Navigate to Project directory
cd VCID_Praxisarbeit_Public

# VM Setup Docker build App Image
sudo docker compose build

# VM Setup Docker initial start App
sudo docker compose up

# VM Setup Docker Create App-Service auto start at reboot (copy Service File docker-App-VCID.service) + register service + start it
cp docker-App-VCID.service /etc/systemd/system/docker-App-VCID.service
sudo systemctl daemon-reload
sudo systemctl enable docker-App-VCID.service
sudo systemctl restart docker-App-VCID.service
