import subprocess
import logging
import argparse
import paramiko

import time
import sys
import warnings
import re

warnings.filterwarnings("ignore")

sys.path.append('/')


def update_and_upgrade_docker_on_other_nodes( ip, ssh, password):

    cmd = "sudo -S yum update && sudo -S yum upgrade -y"

    logging.info("run command : {0}".format(str(cmd)))
    stdin, stdout, stderr = ssh.exec_command(cmd)
    stdin.write(password + "\n")
    stdin.flush()
    print(stdout.read().decode())
    logging.debug(stdout.read().decode())
    logging.error(stderr.read().decode())

def cleanup_vm(ssh, password):

    cmd = "sudo -S yum update -y ; sudo -S package-cleanup --oldkernels --count=1 -y ; sudo -S yum autoremove -y"

    logging.info("run command : {0}".format(str(cmd)))
    stdin, stdout, stderr = ssh.exec_command(cmd)
    stdin.write(password + "\n")
    stdin.flush()
    print(stdout.read().decode())
    logging.debug(stdout.read().decode())
    logging.error(stderr.read().decode())

def run_command_with_password(command, ssh, password):
    logging.debug("\nCommand = " + str(command))
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(command)
    ssh_stdin.write(password + "\n")  # Write the password followed by a newline character
    ssh_stdin.flush()  # Flush the input stream
    output = ssh_stdout.read().decode('utf-8').strip()  # Read and decode the output as a string
    error = ssh_stderr.read().decode('utf-8').strip()  # Read and decode the error as a string
    logging.debug("\nOutput = " + str(output))
    logging.error("\nError = " + str(error))
    return output, error


def check_current_kubeadm_version(ssh, password):
    cmd = "sudo -S kubeadm version"

    output, error = run_command_with_password(cmd, ssh, password)


    if output:
        output =  output.split(",")[2].split(":")[1].strip('"').strip("v")
        logging.debug(output)
        return output
    else:
        logging.error(error)
        return error


def check_current_kubectl_version(ssh, password):
    cmd = "sudo -S kubectl version"

    output, error = run_command_with_password(cmd, ssh, password)

    if output:
        output =  output.split(",")[2].split(":")[1].strip('"').strip("v")
        logging.debug(output)
        return output
    else:
        logging.error(error)


def check_current_kubelet_version(ssh, password):
    cmd = "sudo -S kubelet --version"

    output, error = run_command_with_password(cmd, ssh, password)

    if output:
        output =  output.split(" ")[1].strip("v").strip("\n")
        logging.debug(output)
        return output
    else:
        logging.error(error)
        return error


def fetch_version_via_yum(series, ssh, password):
    cmd = """sudo -S yum list --showduplicates kubeadm --disableexcludes=kubernetes|xargs -n3| awk -F" " '{print $3}'|grep ^""" + series

    output, error = run_command_with_password(cmd, ssh, password)

    if output:
        output = output.split("\n")
        logging.debug(output)
        output = [i.replace("-0", "") for i in output]
        return output
    else:
        logging.error(error)
        return error


# function to update kubeadm
def update_kubeadm(version, node_type, ssh, password):
    cmd = "sudo -S yum install -y kubeadm-" + version + " --disableexcludes=kubernetes"

    output, error = run_command_with_password(cmd, ssh, password)
    logging.info(cmd)

    if output:
        logging.debug(output)
        apply_upgrade(version, node_type, ssh, password)
    else:
        logging.error(error)
        print("command failed %s" % (error))


def upgrade_kubectl(version, ssh, password):
    cmd = "sudo -S yum install -y kubelet-" + version + "-0 kubectl-" + version + "-0 --disableexcludes=kubernetes"

    output, error = run_command_with_password(cmd, ssh, password)
    logging.info(cmd)

    if output:
        logging.debug(output)
        run_command_with_password("sudo -S systemctl daemon-reload", ssh, password)
        run_command_with_password("sudo -S systemctl restart kubelet", ssh, password)
    else:
        logging.error(error)
        print("command failed %s" % (error))


def apply_upgrade(version, node_type, ssh, password):
    version = version.replace("-0", "")
    version1 = "v" + version
    if node_type == "master":
        cmd = "sudo -S kubeadm upgrade apply " + version1 + " -y"

    elif node_type == "worker":
        cmd = "sudo -S kubeadm upgrade node"

    output, error = run_command_with_password(cmd, ssh, password)
    logging.info(cmd)

    if output:
        logging.debug(output)
        upgrade_kubectl(version, ssh, password)
    else:
        logging.error(error)
        print("command failed %s" % (error))


def get_current_version(current_versions_list):
    result = all(element == current_versions_list[0] for element in current_versions_list)
    if result:
        logging.info("All the k8s elements are in the same version")
        output = current_versions_list[0]
        return output
    else:
        logging.info("All the k8s elements aren't in the same version")
        list_output = [item for item in set(current_versions_list) if current_versions_list.count(item) > 1]
        if list_output:
            return list_output[0]
        else:
            return None


def fetch_cluster_detail_worker(password):
    cmd = "kubectl get nodes -o json | jq -r '.items[] | select(.metadata.labels.\"node-role.kubernetes.io/control-plane\"!=\"\") | .status.addresses[] | select(.type==\"InternalIP\") | .address'"

    logging.info("run commands : {0}".format(str(cmd)))
    output, error = subprocess.Popen(cmd,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     stdin=subprocess.PIPE, shell=True).communicate(input=(password + '\n').encode())

    if output:
        output = output.decode().split("\n")
        # Remove empty strings from the output list
        output = [ip for ip in output if ip.strip()]
        logging.debug(output)
        return output
    else:
        logging.error(error)
        return error


def fetch_cluster_detail_master(password):
    cmd = "sudo -S kubectl get nodes -o json | jq -r '.items[] | select(.metadata.labels.\"node-role.kubernetes.io/control-plane\"==\"\") | .status.addresses[] | select(.type==\"InternalIP\") | .address'"

    logging.info("run commands : {0}".format(str(cmd)))
    output, error = subprocess.Popen(cmd,
                                     stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     stdin=subprocess.PIPE, shell=True).communicate(input=(password + '\n').encode())

    if output:
        output = output.decode().split("\n")
        # Remove empty strings from the output list
        output = [ip for ip in output if ip.strip()]
        logging.debug(output)
        return output
    else:
        logging.error(error)
        return error

def main_function(current_versions_list, new_version, node_type, ssh, password):

    current_version = get_current_version(current_versions_list)
    current_version_without_security_patch_version = current_version.rsplit(".", 1)[0]
    current_version_without_security_patch_version_in_number = int(
        current_version_without_security_patch_version.replace(".", ""))
    new_version_without_security_patch_version = new_version.rsplit(".", 1)[0]
    new_version_without_security_patch_version_in_number = int(
        new_version_without_security_patch_version.replace(".", ""))

    while current_version != new_version:
        if new_version_without_security_patch_version_in_number < current_version_without_security_patch_version_in_number:
            break

        output_list = fetch_version_via_yum(current_version_without_security_patch_version, ssh, password)

        if new_version in output_list:
            update_kubeadm(new_version, node_type, ssh, password)
            #run_upgrade_on_other_nodes(new_version, "execute_script")

            kubeadm_current_version = check_current_kubeadm_version(ssh, password)
            kubectl_current_version = check_current_kubectl_version(ssh, password)
            kubelet_current_version = check_current_kubelet_version(ssh, password)

            logging.info("Kubernetes cluster updated to kubectl version %s , kubelet version %s and kubeadm version %s " % (
                kubectl_current_version, kubelet_current_version, kubeadm_current_version))

            if new_version == kubeadm_current_version and new_version == kubelet_current_version and new_version == kubectl_current_version:
                break


        else:
            if current_version == output_list[-1]:
                current_version_without_security_patch_version_in_number = current_version_without_security_patch_version_in_number + 1
                current_version_without_security_patch_version = str(current_version_without_security_patch_version_in_number)
                l = [1]
                for i in l:
                    current_version_without_security_patch_version = current_version_without_security_patch_version[
                                                                     :i] + "." + current_version_without_security_patch_version[
                                                                                 i:]
                current_version = current_version_without_security_patch_version + ".0"
                update_kubeadm(current_version, node_type, ssh, password)
                #run_upgrade_on_other_nodes(current_version, "execute_script")
                current_version = check_current_kubeadm_version(ssh, password)


            else:
                version_to_update = output_list[-1]
                update_kubeadm(version_to_update, node_type, ssh, password)
                #run_upgrade_on_other_nodes(version_to_update, "execute_script")
                kubeadm_current_version = check_current_kubeadm_version(ssh, password)
                kubectl_current_version = check_current_kubectl_version(ssh, password)
                kubelet_current_version = check_current_kubelet_version(ssh, password)
                logging.info("Kubernetes cluster updated to kubectl version %s , kubelet version %s and kubeadm version %s " % (kubectl_current_version, kubelet_current_version, kubeadm_current_version))

                if new_version == kubeadm_current_version and new_version == kubelet_current_version and new_version == kubectl_current_version:
                    break

                current_version_without_security_patch_version = current_version.rsplit(".", 1)[0]
                current_version_without_security_patch_version_in_number = current_version_without_security_patch_version_in_number + 1
                current_version_without_security_patch_version = str(current_version_without_security_patch_version_in_number)
                l = [1]
                for i in l:
                    current_version_without_security_patch_version = current_version_without_security_patch_version[:i] + "." + current_version_without_security_patch_version[i:]
                current_version = current_version_without_security_patch_version + ".0"

    if new_version_without_security_patch_version_in_number < current_version_without_security_patch_version_in_number:
        logging.debug("Downgrade to lower version isn't possible, try upgrading to version > " + current_version)

    else:
        kubeadm_current_version = check_current_kubeadm_version(ssh, password)
        kubectl_current_version = check_current_kubectl_version(ssh, password)
        kubelet_current_version = check_current_kubelet_version(ssh, password)
        if new_version == kubeadm_current_version and new_version == kubelet_current_version and new_version == kubectl_current_version:
            current_version = get_current_version(current_versions_list)
        else:
            current_version = get_current_version(current_versions_list)
            logging.info("cluster's kubectl version %s , kubelet version %s and kubeadm version %s " % (
                kubectl_current_version, kubelet_current_version, kubeadm_current_version))
            logging.error("Upgrade failed for cluster, check the log or retry the upgrade")


def get_current_versions_list(ssh, password):
    kubeadm_current_version = check_current_kubeadm_version(ssh, password)
    kubectl_current_version = check_current_kubectl_version(ssh, password)
    kubelet_current_version = check_current_kubelet_version(ssh, password)
    current_versions_list = [kubeadm_current_version, kubectl_current_version, kubelet_current_version]
    return current_versions_list

def remove_older_kubeadm_backups(ssh, password):
    patterns = ["kubeadm-backup-etcd", "kubeadm-backup-manifest", "kubeadm-upgraded-manifest"]

    for folder_pattern in patterns:
        similar_folder_cmd = f"sudo -S find /etc/kubernetes/tmp -type d -name '{folder_pattern}*' -exec basename {{}} \\;"

        output1, error = run_command_with_password(similar_folder_cmd, ssh, password)
        output1 = output1.split("\n")

        if output1 != "" and len(output1) > 2:
            cmd = f"sudo -S ls -t /etc/kubernetes/tmp/{folder_pattern}* | sed 's/:$//' | tail -n +4 | xargs rm -r"
            output, error = run_command_with_password(cmd, ssh, password)

            if error:
                return error

def adding_gc_for_cleanup(ssh, password):
    print("entered gc cleanup module to add gc to the args file")
    kubeenv_cmd = "echo  '" + 'KUBELET_KUBEADM_ARGS=" --image-gc-high-threshold=80 --image-gc-low-threshold=70 --eviction-hard=imagefs.available<250Mi --eviction-hard=memory.available<250Mi --container-runtime=remote --container-runtime-endpoint=unix:///run/containerd/containerd.sock"' + "'" + " | tee /tmp/kubeadm-flags.env"
    run_command_with_password(kubeenv_cmd, ssh, password)
    run_command_with_password("sudo -S mv /tmp/kubeadm-flags.env /var/lib/kubelet/kubeadm-flags.env", ssh, password)
    run_command_with_password("sudo -S yq write -i /var/lib/kubelet/config.yaml cgroupDriver systemd", ssh, password)
    run_command_with_password("sudo -S systemctl restart kubelet", ssh, password)
    run_command_with_password("sh scripts/patch-security-fixes.sh", ssh, password)

if __name__ == "__main__":
    logging.basicConfig(filename='/tmp/update_kubernetes.log', level=logging.INFO,
                        format='%(asctime)s -  %(levelname)s - %(message)s')
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--version', dest='version', default=None,
                        help="Version to which kubeadm need to be updgrade")

    sshuser = "username"
    sshpassword = "password"

    args = parser.parse_args()
    new_version = args.version
    new_version = new_version.replace("-0", "")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    master_ips = fetch_cluster_detail_master(sshpassword)
    worker_ips = fetch_cluster_detail_worker(sshpassword)
    for worker_ip in worker_ips:
        ssh.connect(worker_ip, username=sshuser, password=sshpassword)
        logging.info("adding changes for gc in kubelet argument file")
        adding_gc_for_cleanup(ssh, sshpassword)
    for master_ip in master_ips:
        ssh.connect(master_ip, username=sshuser, password=sshpassword)
        logging.info("Cleaning vm for upgrading k8s on master %s" % (master_ip))
        cleanup_vm(ssh, sshpassword)
        remove_older_kubeadm_backups(ssh, sshpassword)
        logging.info("Upgrading k8s for master %s" % (master_ip) +" : ")
        logging.info("Upgrading k8s for master %s" % (master_ip) +" : ")
        node_type = "master"
        adding_gc_for_cleanup(ssh, sshpassword)
        current_versions_list = get_current_versions_list(ssh, sshpassword)
        main_function(current_versions_list, new_version, node_type, ssh, sshpassword)
        logging.info("Upgrading docker along with some other dependencies for master %s" % (master_ip) + " ###")
        update_and_upgrade_docker_on_other_nodes(master_ip, ssh, sshpassword)
        run_command_with_password("sudo -S systemctl restart kubelet", ssh, sshpassword)

        logging.info("Finished upgrading Kubernetes in master %s" % (master_ip))



    for worker_ip in worker_ips:
        ssh.connect(worker_ip, username=sshuser, password=sshpassword)
        logging.info("Cleaning vm for upgrading k8s on worker %s" % (worker_ip))
        cleanup_vm(ssh, sshpassword)
        remove_older_kubeadm_backups(ssh, sshpassword)
        logging.info("Upgrading k8s for worker %s" % (worker_ip) +" : ")
        logging.info("Upgrading k8s for worker %s" % (worker_ip) +" : ")
        node_type = "worker"
        current_versions_list = get_current_versions_list(ssh, sshpassword)
        main_function(current_versions_list, new_version, node_type, ssh, sshpassword)
        logging.info("Upgrading docker along with some other dependencies for worker %s" % (worker_ip) + " ###")
        update_and_upgrade_docker_on_other_nodes(worker_ip, ssh, sshpassword)
        run_command_with_password("sudo -S systemctl restart kubelet", ssh, sshpassword)

        logging.info("Finished upgrading Kubernetes in worker %s" % (worker_ip))

    logging.info("all nodes are upgraded to kubernetes version", new_version)
