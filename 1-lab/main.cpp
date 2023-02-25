#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <iostream>
#include <regex>
#include <iomanip>

using namespace std;

const int BUFF_SIZE             = 200;
const int CIDR_MASK_SIZE        = 33;
const int ADDRESS_CHAR_SIZE     = 15;
const int MAC_ADDRESS_CHAR_SIZE = 6;

const uint32_t cidr_mask[] = {
     0x00000000,  0x80000000,  0xC0000000,
     0xE0000000,  0xF0000000,  0xF8000000,
     0xFC000000,  0xFE000000,  0xFF000000,
     0xFF800000, 0xFFC00000, 0xFFE00000,
    0xFFF00000, 0xFFF80000, 0xFFFC0000,
    0xFFFE0000, 0xFFFF0000, 0xFFFF8000,
    0xFFFFC000, 0xFFFFE000, 0xFFFFF000,
    0xFFFFF800, 0xFFFFFC00, 0xFFFFFE00,
    0xFFFFFF00, 0xFFFFFF80, 0xFFFFFFC0,
    0xFFFFFFE0, 0xFFFFFFF0, 0xFFFFFFF8,
    0xFFFFFFFC, 0xFFFFFFFE, 0xFFFFFFFF,
};


void   display_mac_address(const struct ifaddrs* const ifa)
{
    struct ifreq ifr{};

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy((char *)ifr.ifr_name, (const char *)ifa->ifa_name, IFNAMSIZ-1);

    ioctl(fd, SIOCGIFHWADDR, &ifr);

    for (int i = 0; i < MAC_ADDRESS_CHAR_SIZE; i++)
    {
        if (i != MAC_ADDRESS_CHAR_SIZE - 1)
            printf("%.2x:", (ifr.ifr_hwaddr.sa_data[i] + 256) % 256);
        else
            printf("%.2x", (ifr.ifr_hwaddr.sa_data[i]  + 256) % 256);
    }
    printf("\n");

    close(fd);
}

[[nodiscard]]
char*  get_ip_address(const struct ifaddrs* const ifa)
{
    auto pIn = (struct sockaddr_in*)ifa->ifa_addr;
    char *_ip= (char*)calloc(BUFF_SIZE, sizeof(char*));
    inet_ntop(ifa->ifa_addr->sa_family, (void*)&pIn->sin_addr, _ip , BUFF_SIZE);
    return _ip;
}

[[nodiscard]]
char*  get_netmask(const struct ifaddrs* const ifa)
{
    auto pIn = (struct sockaddr_in *) ifa->ifa_netmask;
    char *_netmask = (char*)calloc(BUFF_SIZE, sizeof(char*));
    inet_ntop(ifa->ifa_addr->sa_family, (void*)&pIn->sin_addr , _netmask, BUFF_SIZE);
    return _netmask;
}

[[nodiscard]]
string get_byte_from_address(const string& src, int& begin_pos)
{
    string dest;
    int point_pos = (int)src.find('.', begin_pos);
    if (point_pos != string::npos)
        dest = src.substr(begin_pos, point_pos - begin_pos);
    begin_pos = point_pos;
    return dest;
}

char   get_cidr_and_templateAddr(string _netmask, string _ip, string& templateAddr)
{
    uint32_t cidr = 0;

    _ip += ".";
    _netmask += ".";

    for (int i1 = 0, i2 = 0, base = 24 ;; i1++, i2++, base -= 8)
    {
        string buff1 = get_byte_from_address(_netmask, i1);
        string buff2 = get_byte_from_address(_ip, i2);
        if (i1 < 0 || i2 < 0)
            break;

        unsigned char uc_buff1 = stoi(buff1);
        cidr = cidr | (uc_buff1 << base);
        templateAddr += to_string(uc_buff1 & stoi(buff2));

        if (base > 0)
            templateAddr += ".";
    }

    char cidr_mask_pos = 0;
    for (char i = 0; i < CIDR_MASK_SIZE; i++)
    {
        if (cidr == cidr_mask[i])
        {
            cidr_mask_pos = i;
            break;
        }
    }

    return cidr_mask_pos;
}

void   search_for_devices(const string& templateAddr, const int& cidr)
{
    string command = "sudo nmap -sn " + templateAddr + "/" + to_string(cidr);

    char *nmap_output = nullptr;
    int file_size = 0;

    try
    {
        FILE *ostream = popen((const char *)command.c_str(), "r");
        if (ostream == nullptr)
        {
            cout << "Error: occurred while reading nmap output." << "\n";
            exit(1);
        }
        char ch;
        while ((ch = (char)fgetc(ostream)) != EOF)
        {
            nmap_output = (char *)realloc(nmap_output, sizeof(char) * (++file_size));
            nmap_output[file_size - 1] = ch;
        }
        nmap_output[file_size] = '\0';
        fclose(ostream);
    }
    catch(...)
    {
        cout << "Error: occurred while reading nmap output." << "\n";
        exit(1);
    }
    string str_nmap_output = nmap_output;
    string temp = str_nmap_output;

    vector<string> v_macs, v_ips;
    smatch smacs, sips;

    while(regex_search(str_nmap_output, smacs, regex("([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}")))
    {
        v_macs.push_back(smacs.str(0));
        str_nmap_output = smacs.suffix().str();
    }

    str_nmap_output = temp;
    while(regex_search(str_nmap_output, sips, regex("([[:digit:]]{1,3}\\.){3}[[:digit:]]{1,3}")))
    {
        v_ips.push_back(sips.str(0));
        str_nmap_output = sips.suffix().str();
    }

    cout << "\tInformation of connected devices to this interface:\n";
    for (int i = 0, n = (int)v_macs.size(); i < n; i++)
        cout <<  setw(38) << i + 1 << ". inet: " << setw(ADDRESS_CHAR_SIZE) << v_ips[i] << "\tether: " <<  setw(ADDRESS_CHAR_SIZE) << v_macs[i];
}

void   search(const string &filter, const string &ifa_name)
{
    struct ifaddrs *pIfaddrs, *ifa;
    getifaddrs(&pIfaddrs);

    bool filter_flag = !(filter == "-l");
    bool found_flag = false;

    for (ifa = pIfaddrs; ifa; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_addr->sa_family != AF_INET || (filter_flag && (ifa->ifa_name != ifa_name)))
            continue;
        found_flag = true;
        cout << ifa->ifa_name << ":\n";
        string _netmask = get_netmask(ifa);
        string _ip = get_ip_address(ifa);

        cout << "\tnetmask: " << setw(ADDRESS_CHAR_SIZE) << _netmask << "\tinet: " << setw(ADDRESS_CHAR_SIZE) << _ip;

        if (strcmp(ifa->ifa_name, "lo") != 0)
        {
            cout << "\tether: ";
            display_mac_address(ifa);

            string templateAddr;
            char cidr = get_cidr_and_templateAddr(_netmask, _ip, templateAddr);
            search_for_devices(templateAddr, cidr);
        }

        cout << "\n";
    }
    if (!found_flag && filter_flag)
    {
        cout << "Error: incorrect name." << "\n";
        exit(1);
    }
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        cout << "Error: missing parameters." << "\n";
        exit(1);
    }
    string option;
    try
    {
        option = argv[1];
    }
    catch(...)
    {
        cout << "Error: incorrect option." << "\n";
        exit(1);
    }

    if (option == "-l")
        search(option, "");
    else
        search("", option);

    return 0;
}