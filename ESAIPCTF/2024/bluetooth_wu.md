# Bluetooth forensics challenge - ESAIPCTF 2024 - Write up 
#### By eddym@lou

I solved this challenge during the ESAIPCTF 2024. This challenge was labelled with the **forensics** category and difficulty was set to **medium**. We are given a network capture file containing bluetooth exchange and we have to extract sensitive information from it. 

Running the **strings** command on the bluetooth.pcapng shows several devices names such as "LAPTOP-M7O49DS9", "OnePlus 8T", "LE-Philips TAH8506" and "Redmi 9T". Bluetooth devices include a name in their advertisement packets so that they can be identified more easily, we can assume that these devices are communicating over bluetooth in the packet capture. 
Another notable thing in the strings is the present of PDF headers and data as shown in figure 1 : 

![PDF Header in strings](/ESAIPCTF/2024/images/1.PDF_header_in_strings.png)
*Figure 1 : PDF Header in strings*

Next step is to open up the file in wireshark and start going through the packets in order to understand what happened. 
Looking at the source and destination columns of the packet, we identify a lot of communication going on between a "host" and a "controller". 

In the Bluetooth protocol, the host is responsible for high-level operations like device discovery, connection, and handling protocols like L2CAP, OBEX, and GATT. The controller, on the other hand, handles lower-level operations such as sending and receiving packets (radio transmission, modulation, encryption, etc.). These components communicate via the HCI protocol (Host Controller Interface).

However, in order to make bluetooth devices more compact and efficient (in terms of performance and cost) they often are part of the same physical device. The host and controller do not directly communicate over Bluetooth : they communicate via the HCI protocol (Host Controller Interface).

HCI involves three main types of packets: HCI commands, events, and ACL data. The host sends HCI commands to the controller, which responds with HCI events and ACL data as needed. These packets are common in the capture, as shown in Figure 2.

![HCI communication between host and controller](/ESAIPCTF/2024/images/2.HCI_CMD_and_EVT.png)
*Figure 2 : HCI communication between host and controller*

In this screenshot (figure 3), the host sends HCI commands to request the remote name of a connected device, the link quality, the RSSI (Received Signal Strength Indication), or the TX power level. The controller responds with the corresponding data via HCI event packets. The remote name of the device is "Redmi 9T" and it is linked to **22:22:48:08:a5:80**.

![HCI event answer for the remote device name](/ESAIPCTF/2024/images/3.Remote_name_answer.png)
*Figure 3 : HCI event answer for the remote device name*

Taking a closer look at the following packets, we spot this very same mac address again. The Redmi 9T phone is being paired to our local device (c.f Figure 4). And they start to initiate an object exchange. 

![Pairing between local device and phone, and OBEX](/ESAIPCTF/2024/images/4.Communication_between_loopback_and_redmi9T.png)
*Figure 4 : Pairing between local device and phone, and OBEX*

OBEX (![OBject EXchange](https://en.wikipedia.org/wiki/OBject_EXchange)) is a high-level protocol that operates within the Bluetooth protocol stack (as shown on figure 5). It is primarily used for exchanging binary objects (files/images/songs/contacts..) between Bluetooth devices. 

![Bluetooth stack illustration](/ESAIPCTF/2024/images/5.Bluetooth_stack_illustration_obex.JPG)
*Figure 5 : Bluetooth stack illustration* ![Source](http://bluetoothtechnology-info.blogspot.com/2008/04/bluetooth-stack.html)

This seems very promising as we are requested to retrieve sensitive information from the capture. Putting this discovery in perspective with the PDF header found in the output of the strings commands, we can use a wireshark filter to pin down where this header is coming from : 

![Wireshark filter to pin down the PDF file header](/ESAIPCTF/2024/images/6.Wireshark_filter_PDF_header.png)
*Figure 6 : Wireshark filter to pin down the PDF file header*

Looking closely at the data field of this packet confirms it is the start of a PDF file, and its name is "echange_secret.pdf" : seems like we're on the right track : 

![Echange secret PDF HEADER](/ESAIPCTF/2024/images/7.Echange_secret.png)

*Figure 7 : PDF header containing echange secret*

Let's change our wireshark filter to **bluetooth.addr == 22:22:48:08:a5:80** to get the full object exchange between our device and the phone. 

![Wireshark filter full object exchange](/ESAIPCTF/2024/images/8.Wireshark_filter_obex_exchange.png)
*Figure 8 : Wireshark filter obex exchange*

SDU (Service Data Unit) is a unit of data exchanged between the OBEX client and server during object exchange transactions. 
It represents the application-layer data that is being transmitted or received : in our case the pdf file.
The file is sent in several packets due to the segmentation and fragmentation required to transmit the SDU over the Bluetooth link efficiently and reliably. Each packet carries a portion of the file's data along with protocol headers and control information necessary for the OBEX exchange.

Wireshark supports a wide variety of protocoles and has a lot of already prebuilt modules such as object parsers. If you go to "file" -> export HTTP/SMB/FTP/TFTP object, wireshark will parse the packets and extract the raw payload of each packet (without the protocole's headers) in order to rebuilt any files sent via these protocoles. Unfortunely for us, wireshark (in it's classic edition) doesn't support an OBEX Object parser module. Looking online for such tools without very successfull easier : we need to do it manually.
First off we have to extract the raw data payload on each packet in the Obex exchange.
For each packet, right click on the bytes and "copy raw data as b64". Then echo -n "b64data" > n. With n being the number of the packet.
We now have the pdf data, split in 10 files. Then we need to get rid of the headers of the Obex protocol.
Let's go back to wireshark and count how many bytes are included before the actual data payload. We count 11 bytes before the start of the payload, and 2 bytes at the end as checksum. In total we need to trim out 13 bytes to get the actual raw payload : 
![Hex dump](/ESAIPCTF/2024/images/9.headers_in_obex.png)
*Figure 9 : Headers in Obex*

Let's write a shell script to do this for us : 
```#!/bin/bash
inputfile=$1
echo $inputfile
filesize=$(stat -c%s $inputfile)
echo $filesize
outsize=$((filesize - 13))
echo $outsize
dd if=$inputfile of=$inputfile.clean bs=1 skip=11 count=$outsize
```

This script parses the first argument given upon execution and stores it into *inputfile*. Then we print the filesize of this file and store this into the variable *filesize*. We define a variable *outsize* by taking the *filesize* and substracting 13 bytes (11 bytes of Obex headers + 2 checksum bytes). And finally we use dd to parse the input file, skip the first 11 bytes and to write a new file as *inputfile.clean* by using *outsize* (doing so it also gets rid of the 2 final bytes).

![Hex dump](/ESAIPCTF/2024/images/10.execution_of_our_script.png)
*Figure 10 : Execution of our script*

We can now rebuild our pdf file ! Let's to a simple `cat 1.clean 2.clean 3.clean ... 10.clean > echanges_secret.pdf` and voilà : 

![Hex dump](/ESAIPCTF/2024/images/11.Echange_secret_flag.png)
*Figure 11 : the flag on the restored pdf file*

