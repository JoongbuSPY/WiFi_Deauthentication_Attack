#include <tins/tins.h>
#include <iostream>
#include <pcap.h>
#include <arpa/inet.h>
#include <string>
#include <string>
#include <set>

using namespace Tins;
using namespace std;

using std::set;


typedef Dot11::address_type address_type;
typedef set<address_type> ssids_type;


void Call_Device(char **C_dev);
char *dev;
pcap_if_t *alldevs;
pcap_if_t *d;
int i=0;
char buf[65000];
char Select_device[10];
char errbuf[PCAP_ERRBUF_SIZE];
PacketSender sender;
ssids_type ssids;

int main(int argc, char *argv[])
{

    printf("\t\t\t**********************************\n");
    printf("\t\t\t*WiFi Deauthentication Attack!!!!*\n");
    printf("\t\t\t**********************************\n\n");


    if (pcap_findalldevs(&alldevs, errbuf) == -1)
        fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);

    for(d=alldevs;d;d=d->next)
        printf("%d. %s\n", ++i, d->name);

    if(i==0)
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");

    printf("\nSelect Device: ");
    scanf("%s",&Select_device);
    dev = Select_device;
    system("clear");

    // libtins
    SnifferConfiguration config;
    config.set_promisc_mode(true);
    //config.set_rfmon(true);
    config.set_filter("type mgt subtype beacon");
    Sniffer sniffer(dev,config);

    while(Packet pkt = sniffer.next_packet())
    {
        Dot11Beacon beacon = pkt.pdu()->rfind_pdu<Dot11Beacon>();

        if(!beacon.from_ds() && !beacon.to_ds())
        {
            address_type addr = beacon.addr2();

            ssids_type::iterator it = ssids.find(addr);

            if(it == ssids.end())
            {
                string ssid = beacon.ssid();
                ssids.insert(addr);
                cout << addr << " - " << ssid << endl;
            }
        }
    }
}






