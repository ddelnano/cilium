#!/usr/bin/env bash

dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
source "${dir}/../helpers.bash"
# dir might have been overwritten by helpers.bash
dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

function abort {
	set +x

	echo "------------------------------------------------------------------------"
	echo "                          K8s Test Failed"
	echo "$*"
	echo ""
	echo "------------------------------------------------------------------------"

	cilium_id=$(docker ps -aq --filter=name=cilium-agent)
	echo "------------------------------------------------------------------------"
	echo "                            Cilium logs"
	docker logs ${cilium_id}
	echo ""
	echo "------------------------------------------------------------------------"

	exit 1
}

function gather_k8s_logs {
  local CILIUM_POD_1=$1
  local CILIUM_POD_2=$2
  local LOCAL_NODE_NUM=$3
  local LOGS_DIR=$4

  mkdir -p ${LOGS_DIR}
  kubectl logs -n kube-system ${CILIUM_POD_1} > ${LOGS_DIR}/${CILIUM_POD_1}-logs || true
  kubectl logs -n kube-system ${CILIUM_POD_2} > ${LOGS_DIR}/${CILIUM_POD_2}-logs || true
  kubectl logs -n kube-system kube-apiserver-k8s-1 > ${LOGS_DIR}/kube-apiserver-k8s-1-logs || true
  kubectl logs -n kube-system kube-controller-manager-k8s-1 > ${LOGS_DIR}/kube-controller-manager-k8s-1-logs || true
  journalctl -au kubelet > ${LOGS_DIR}/kubelet-k8s-${LOCAL_NODE_NUM}-logs || true
}
