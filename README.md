# netfilter-test
This program blocks host given by argument!

## How to drop ip packets using iptables
sudo iptables -A INPUT -j NFQUEUE
sudo iptables -A OUTPUT -j NFQUEUE
sudo iptables -L

## How to reset above settings using iptables
sudo iptables -D INPUT -j NFQUEUE
sudo iptables -D OUTPUT -j NFQUEUE
sudo iptables -L

## CAPTURE
Below, you can find out that test.gilgil.net is blocked!

![iptable_block](https://user-images.githubusercontent.com/31784008/139526384-3a0eb540-869e-4a78-a468-4ca4fae1506f.PNG)
