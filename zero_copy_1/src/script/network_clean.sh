#!/bin/bash
ip netns delete container4
ip netns delete container5
ip netns delete container6
ip netns delete client1
ip link delete br0 