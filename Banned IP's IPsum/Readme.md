\# MikroTik IPsum Blacklist Importer



This MikroTik RouterOS v7 script automatically downloads the IPsum blacklist and imports the IP addresses into a MikroTik Firewall Address List.



The script uses the official IPsum `levels/3.txt` feed, which contains IP addresses that appear on at least three blacklists.



\## Features



\* Compatible with MikroTik RouterOS v7

\* Automatically downloads the IPsum blacklist

\* Uses the `levels/3.txt` feed

\* Reads large files using `/file read`

\* Supports files larger than the `/file get contents` limit

\* Processes the file in chunks

\* Correctly handles lines split across chunk boundaries

\* Imports addresses into a temporary address list first

\* Replaces the active blacklist only after a successful import

\* Protects against empty or corrupted downloads

\* Keeps manually added entries in the `ipsum` address list

\* Supports HTTPS certificate validation

\* Suitable for use with the MikroTik Scheduler



\## IPsum



This script uses:



```text

https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt

```



IPsum is a collection of suspicious and malicious IP addresses gathered from multiple public threat intelligence sources.



More information:



```text

https://github.com/stamparm/ipsum

```



The `levels/3.txt` feed contains IP addresses that appear in at least three different blacklists.



This generally provides a better balance between protection and false positives than importing the complete IPsum list.



\## Requirements



\* MikroTik RouterOS v7

\* Working internet connection

\* Working DNS configuration

\* HTTPS access to GitHub

\* Correct CA certificates when using `check-certificate=yes`



The examples in this README assume that the WAN interface is:



```text

ether1

```



\## Installation



Create a new script:



```routeros

/system script add name=update-ipsum policy=read,write,test

```



Then open the script and paste the following code into the `source` field.



```routeros

\# ============================================================

\# IPsum blacklist importer for MikroTik RouterOS v7

\#

\# Source:

\# https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt

\#

\# Existing production address list:

\#   ipsum

\#

\# Temporary address list:

\#   ipsum-new

\#

\# Entries managed by this script use:

\#   comment="IPsum managed"

\#

\# Manually-added entries in list=ipsum with another comment

\# will NOT be removed.

\# ============================================================





\# -----------------------------

\# Configuration

\# -----------------------------



:local url "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"

:local fileName "ipsum-level3.txt"



:local finalList "ipsum"

:local tempList "ipsum-new"



:local entryComment "IPsum managed"



:local chunkSize 32768





\# -----------------------------

\# Start

\# -----------------------------



:log info "IPsum: starting blacklist update"





\# -----------------------------

\# Remove old downloaded file

\# -----------------------------



:if (\[:len \[/file find where name=$fileName]] > 0) do={

&#x20;   /file remove \[find where name=$fileName]

}





\# -----------------------------

\# Clean temporary address list

\# -----------------------------



/ip firewall address-list remove \[find where list=$tempList]





\# -----------------------------

\# Download new blacklist

\# -----------------------------



:log info "IPsum: downloading blacklist"



:local fetchOK false



:onerror fetchError in={



&#x20;   :local fetchResult \[/tool fetch \\

&#x20;       url=$url \\

&#x20;       dst-path=$fileName \\

&#x20;       check-certificate=yes \\

&#x20;       as-value]



&#x20;   :if (($fetchResult->"status") = "finished") do={

&#x20;       :set fetchOK true

&#x20;   }



} do={



&#x20;   :log error ("IPsum: download failed - " . $fetchError)



}





:if (!$fetchOK) do={

&#x20;   :log error "IPsum: update aborted because download failed"

&#x20;   :error "IPsum download failed"

}





\# -----------------------------

\# Verify downloaded file exists

\# -----------------------------



:local fileID \[/file find where name=$fileName]



:if (\[:len $fileID] = 0) do={

&#x20;   :log error "IPsum: downloaded file does not exist"

&#x20;   :error "IPsum file missing"

}





\# -----------------------------

\# Get downloaded file size

\# -----------------------------



:local fileSize \[/file get $fileID size]



:log info ("IPsum: downloaded " . $fileSize . " bytes")





:if ($fileSize < 1000) do={



&#x20;   :log error ("IPsum: downloaded file is unexpectedly small: " . $fileSize . " bytes")



&#x20;   /file remove $fileID



&#x20;   :error "IPsum downloaded file too small"

}





\# -----------------------------

\# Parser variables

\# -----------------------------



:local offset 0

:local carry ""

:local imported 0

:local rejected 0





\# -----------------------------

\# Read file in chunks

\# -----------------------------



:while ($offset < $fileSize) do={



&#x20;   :local readSize $chunkSize



&#x20;   :if (($offset + $readSize) > $fileSize) do={

&#x20;       :set readSize ($fileSize - $offset)

&#x20;   }





&#x20;   :local readResult \[/file read \\

&#x20;       file=$fileName \\

&#x20;       offset=$offset \\

&#x20;       chunk-size=$readSize \\

&#x20;       as-value]



&#x20;   :local data ($readResult->"data")





&#x20;   :set data ($carry . $data)

&#x20;   :set carry ""





&#x20;   :local position 0

&#x20;   :local dataLength \[:len $data]

&#x20;   :local lineEnd \[:find $data "\\n" $position]





&#x20;   :while (\[:typeof $lineEnd] != "nil") do={



&#x20;       :local line \[:pick $data $position $lineEnd]





&#x20;       :if (\[:len $line] > 0) do={



&#x20;           :if (\[:pick $line (\[:len $line] - 1) \[:len $line]] = "\\r") do={

&#x20;               :set line \[:pick $line 0 (\[:len $line] - 1)]

&#x20;           }

&#x20;       }





&#x20;       :if (\[:len $line] > 0) do={



&#x20;           :local addOK true



&#x20;           :onerror addError in={



&#x20;               /ip firewall address-list add \\

&#x20;                   list=$tempList \\

&#x20;                   address=$line \\

&#x20;                   comment=$entryComment



&#x20;           } do={



&#x20;               :set addOK false



&#x20;           }





&#x20;           :if ($addOK) do={



&#x20;               :set imported ($imported + 1)



&#x20;           } else={



&#x20;               :set rejected ($rejected + 1)

&#x20;               :log warning ("IPsum: rejected invalid entry: " . $line)



&#x20;           }

&#x20;       }





&#x20;       :set position ($lineEnd + 1)

&#x20;       :set lineEnd \[:find $data "\\n" $position]

&#x20;   }





&#x20;   :if ($position < $dataLength) do={

&#x20;       :set carry \[:pick $data $position $dataLength]

&#x20;   }





&#x20;   :set offset ($offset + $readSize)

}





\# -----------------------------

\# Process final leftover line

\# -----------------------------



:if (\[:len $carry] > 0) do={



&#x20;   :if (\[:pick $carry (\[:len $carry] - 1) \[:len $carry]] = "\\r") do={

&#x20;       :set carry \[:pick $carry 0 (\[:len $carry] - 1)]

&#x20;   }





&#x20;   :local addOK true



&#x20;   :onerror addError in={



&#x20;       /ip firewall address-list add \\

&#x20;           list=$tempList \\

&#x20;           address=$carry \\

&#x20;           comment=$entryComment



&#x20;   } do={



&#x20;       :set addOK false



&#x20;   }





&#x20;   :if ($addOK) do={



&#x20;       :set imported ($imported + 1)



&#x20;   } else={



&#x20;       :set rejected ($rejected + 1)

&#x20;       :log warning ("IPsum: rejected invalid final entry: " . $carry)



&#x20;   }

}





\# -----------------------------

\# Sanity check

\# -----------------------------



:if ($imported < 1000) do={



&#x20;   :log error ("IPsum: only " . $imported . " addresses imported - keeping existing blacklist")



&#x20;   /ip firewall address-list remove \[find where list=$tempList]



&#x20;   :if (\[:len \[/file find where name=$fileName]] > 0) do={

&#x20;       /file remove \[find where name=$fileName]

&#x20;   }



&#x20;   :error "IPsum import sanity check failed"

}





\# -----------------------------

\# Import successful

\# -----------------------------



:log info ("IPsum: successfully parsed " . $imported . " addresses")



:if ($rejected > 0) do={

&#x20;   :log warning ("IPsum: rejected " . $rejected . " invalid entries")

}





\# -----------------------------

\# Remove previous managed IPsum entries

\# -----------------------------



:log info "IPsum: replacing existing managed blacklist"



/ip firewall address-list remove \[

&#x20;   find where list=$finalList comment=$entryComment

]





\# -----------------------------

\# Move temporary entries into production

\# -----------------------------



/ip firewall address-list set \\

&#x20;   \[find where list=$tempList] \\

&#x20;   list=$finalList





\# -----------------------------

\# Delete downloaded file

\# -----------------------------



:if (\[:len \[/file find where name=$fileName]] > 0) do={

&#x20;   /file remove \[find where name=$fileName]

}





\# -----------------------------

\# Finished

\# -----------------------------



:log info ("IPsum: update complete - imported=" . $imported . " rejected=" . $rejected)

```



\## Running the Script Manually



Run the script with:



```routeros

/system script run update-ipsum

```



Monitor the logs with:



```routeros

/log print follow

```



A successful update should look similar to:



```text

IPsum: starting blacklist update

IPsum: downloading blacklist

IPsum: downloaded 2xxxxx bytes

IPsum: successfully parsed 1xxxx addresses

IPsum: replacing existing managed blacklist

IPsum: update complete - imported=1xxxx rejected=0

```



\## Checking the Address List



Check how many addresses were imported:



```routeros

/ip firewall address-list print count-only where list=ipsum

```



To view the complete list:



```routeros

/ip firewall address-list print where list=ipsum

```



\## Firewall Configuration



The script intentionally does not create firewall rules.



This allows you to decide how the blacklist should be used.



\### Protecting the Router



If `ether1` is your WAN interface:



```routeros

/ip firewall filter

add chain=input \\

&#x20;   in-interface=ether1 \\

&#x20;   src-address-list=ipsum \\

&#x20;   action=drop \\

&#x20;   comment="Drop IPsum blacklist to router"

```



This blocks traffic from IP addresses in the blacklist that is destined for the MikroTik router itself.



\## Protecting LAN Devices and Servers



If you also want to block blacklisted IP addresses from reaching devices behind the MikroTik:



```routeros

/ip firewall filter

add chain=forward \\

&#x20;   in-interface=ether1 \\

&#x20;   src-address-list=ipsum \\

&#x20;   action=drop \\

&#x20;   comment="Drop IPsum blacklist to LAN"

```



Firewall rule order is important.



The drop rule must be placed before more general accept rules that would otherwise allow the same traffic.



\## RAW Firewall



For large blacklists it may be more efficient to drop traffic before connection tracking.



Example:



```routeros

/ip firewall raw

add chain=prerouting \\

&#x20;   in-interface=ether1 \\

&#x20;   src-address-list=ipsum \\

&#x20;   action=drop \\

&#x20;   comment="Drop IPsum blacklist before connection tracking"

```



The advantage of using RAW is that unwanted traffic can be dropped before it enters the connection tracking table.



Always verify that RAW rules are appropriate for your existing firewall configuration.



\## Automatic Updates with Scheduler



For example, to update the list every day at 03:00:



```routeros

/system scheduler

add name=update-ipsum \\

&#x20;   start-time=03:00:00 \\

&#x20;   interval=1d \\

&#x20;   on-event="/system script run update-ipsum"

```



Check the scheduler with:



```routeros

/system scheduler print

```



\## HTTPS Certificates



The script uses:



```routeros

check-certificate=yes

```



This causes RouterOS to validate GitHub's HTTPS certificate.



If you receive an error such as:



```text

SSL: no trusted CA certificate found

```



check the RouterOS certificate configuration.



For example:



```routeros

/certificate/settings print

```



On supported RouterOS v7 versions, you can also inspect the built-in CA certificates:



```routeros

/certificate/builtin/print

```



It is not recommended to permanently disable certificate validation.



For troubleshooting only, you can temporarily test with:



```routeros

check-certificate=no

```



Once the CA configuration is correct, use:



```routeros

check-certificate=yes

```



again.



\## Why `/file read` Is Used



RouterOS has a size limitation when using:



```routeros

/file get <file> contents

```



The IPsum feed can be larger than this limit.



For this reason, the script uses:



```routeros

/file read

```



The file is processed in chunks:



```routeros

chunk-size=32768

```



An IP address line can be split exactly at the boundary between two chunks.



The script therefore uses the:



```text

carry

```



variable.



Any incomplete line at the end of one chunk is stored and added to the beginning of the next chunk.



This ensures that no IP addresses are lost during parsing.



\## Safe Updates



New IP addresses are first imported into:



```text

ipsum-new

```



The active production list:



```text

ipsum

```



remains untouched while the new blacklist is being downloaded and parsed.



Only after enough addresses have been imported successfully will the script replace the existing managed entries.



The default sanity check is:



```routeros

:if ($imported < 1000)

```



If fewer than 1000 addresses are imported:



\* `ipsum-new` is deleted

\* the existing `ipsum` list remains active

\* the script stops with an error



This prevents an empty, corrupted, or unexpected download from wiping the existing blacklist.



\## Keeping Manual Entries



The script only removes entries with:



```text

comment="IPsum managed"

```



A manually created entry such as:



```routeros

/ip firewall address-list

add list=ipsum \\

&#x20;   address=192.0.2.50 \\

&#x20;   comment="Manual blacklist"

```



will not be removed during an IPsum update.



\## Troubleshooting



\### Download Fails



Test the download manually:



```routeros

/tool fetch \\

&#x20;   url="https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt" \\

&#x20;   dst-path="ipsum-test.txt" \\

&#x20;   check-certificate=yes

```



Then check whether the file exists:



```routeros

/file print

```



\### File Downloads but 0 Addresses Are Imported



Test whether `/file read` returns data:



```routeros

:local x \[/file read \\

&#x20;   file="ipsum-level3.txt" \\

&#x20;   offset=0 \\

&#x20;   chunk-size=100 \\

&#x20;   as-value]



:put ($x->"data")

```



You should see multiple IPv4 addresses.



\### Check the Number of Imported Addresses



```routeros

/ip firewall address-list print count-only where list=ipsum

```



\### View IPsum Log Messages



```routeros

/log print where message\~"IPsum"

```



Or monitor the log live:



```routeros

/log print follow

```



\## Security Notes



An external IP blacklist is not a replacement for a properly configured firewall.



You should also consider:



\* Using a default-deny policy from WAN

\* Exposing only required management services

\* Restricting WinBox, SSH, and API access

\* Using interface lists where appropriate

\* Keeping RouterOS up to date

\* Using strong authentication

\* Restricting management services to trusted source IP ranges

\* Using connection tracking and RAW rules appropriately

\* Reviewing blacklist behavior before deploying it in production



\## Credits



Blacklist data provided by:



\*\*IPsum\*\*



Repository:



```text

https://github.com/stamparm/ipsum

```



MikroTik RouterOS:



```text

https://mikrotik.com/

```



\## Disclaimer



This script is provided without warranty.



External threat intelligence feeds can contain false positives. Always test the configuration before deploying it in a production environment.



The user is responsible for firewall rules, network access, and any traffic that may be blocked as a result of using this blacklist.



\## License



You can publish this project under the MIT License.



See:



```text

LICENSE

```



