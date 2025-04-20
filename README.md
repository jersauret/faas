# faas

1. Install Minikube
   Follow the official installation guide for your OS:
   
   
   https://minikube.sigs.k8s.io/docs/start/
2. Install kubectl
   
   ```bash
   curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
   sudo install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl
   ```
   
   
3. Start minkube
   
   ``` bash
   minikube start
   ```
   
   
   in case of problems you can try
   
   ```bash
   minikube stop
   minikube delete # This will remove the existing cluster
   minikube start --driver=docker --memory=4096 --cpus=2
   ```
   
   
   Check it is working
   
   ```bash
   kubectl get nodes
   ```
   
   
   
4. Install OpenFaas
   
   ```bash
   curl -sLS https://get.arkade.dev | sudo sh
   arkade install openfaas
   ```
   
   
   
5. Get the OpenFaaS credentials
   
   ```bash
   PASSWORD=$(kubectl get secret -n openfaas basic-auth -o jsonpath="{.data.basic-auth-password}" | base64 --decode; echo)
   echo "OpenFaaS admin password: $PASSWORD"
   ```
   
   
6. Install the OpenFaaS CLI
   
   ```bash
   curl -sSL https://cli.openfaas.com | sudo sh
   ```
   
   
7. Forward the gateway to your machine
   
   ```bash
   kubectl port-forward -n openfaas svc/gateway 8080:8080 &
   ```
   
   
8. Log in to OpenFaaS
   
   ```bash
   export OPENFAAS_URL=http://127.0.0.1:8080
   faas-cli login --password $PASSWORD
   ```
   
   
9. Check template list
   
   ```bash
   faas-cli template store list
   ```
   
   
10. Create function (python3-http example)
    
    ```bash
    faas-cli new --lang python3-http hello-python
    ```
    
    
    Modify as you wish
11. Build and deploy (.yml file name may vary.. not sure)
    
    ```bash
    faas-cli up -f hello-python.yml
    ```
    
    
    
12. Check ui @
    http://127.0.0.1:8080/
