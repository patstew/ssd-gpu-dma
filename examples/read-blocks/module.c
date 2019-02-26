#include "args.h"
#include "read.h"
#include <nvm_types.h>
#include <nvm_ctrl.h>
#include <nvm_dma.h>
#include <nvm_aq.h>
#include <nvm_error.h>
#include <nvm_util.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>

void* mem = NULL;
uint64_t addr;

bool setup_map() {
    /*
	int fd = open( "/dev/uio0" , O_RDWR );
	if( fd < 0 ) {
		fprintf(stderr, "MapResv : Unable to open /dev/uio0" );
        return false;
	}

	mem = mmap( NULL , 128*1024*1024 , PROT_READ|PROT_WRITE , MAP_SHARED , fd , 0 );
	addr = 0x38000000;

    if( (intptr_t) mem == -1 ) {
		fprintf(stderr, "MapResv : Unable to map reserved memory" );
        return false;
	}

	if( close( fd ) ) {
        fprintf(stderr, "MapResv : Error closing file descriptor" );
        return false;
    }
    */

    int fd = open( "/dev/dma" , O_RDWR | O_CLOEXEC );
	if( fd < 1 ) {
        fprintf(stderr, "Failed to open /dev/dma\n");
        return false;
	}

	mem = mmap( NULL , 128*1024*1024 , PROT_READ|PROT_WRITE , MAP_SHARED , fd , 0 );
	if( (int) mem == -1 ) {
        fprintf(stderr, "Failed to mmap dma %i %s\n", errno, strerror(errno));
        return false;
	}

    int status = ioctl(fd, _IOR(0xF0, 0, uint64_t*), &addr);
    if (status < 0)
    {
        fprintf(stderr, "Page mapping kernel request failed: %s\n", strerror(errno));
        return false;
    }

    fprintf(stderr, "Successfully mapped %p %llX\n", mem, addr);

    return true;
}

void close_map() {
    munmap(mem, 128*1024*1024);
}

int test_dma_map(nvm_dma_t** handle, const nvm_ctrl_t* ctrl, void** vaddr, size_t size) {
    size = NVM_CTRL_ALIGN(ctrl, size);
    int r = nvm_dma_map(handle, ctrl, mem, size, 1, &addr);
    if (vaddr)
        *vaddr = mem;
    mem += size;
    addr += size;
    return r;
}

/* 
 * Bus-device-function descriptor.
 * Used to identify a device/function in the PCI tree.
 */
struct bdf
{
    int     domain;
    int     bus;
    int     device;
    int     function;
};

static int pci_enable_device(const struct bdf* dev)
{
    char path[64];
    sprintf(path, "/sys/bus/pci/devices/%04x:%02x:%02x.%x/enable",
            dev->domain, dev->bus, dev->device, dev->function);

    FILE *fp = fopen(path, "w");
    if (fp == NULL)
    {
        fprintf(stderr, "Failed to open file descriptor: %s\n", strerror(errno));
        return errno;
    }

    fputc('1', fp);
    fclose(fp);
    return 0;
}


/*
 * Allow device to do DMA.
 */
static int pci_set_bus_master(const struct bdf* dev)
{
    char path[64];
    sprintf(path, "/sys/bus/pci/devices/%04x:%02x:%02x.%x/config", 
            dev->domain, dev->bus, dev->device, dev->function);

    FILE* fp = fopen(path, "r+");
    if (fp == NULL)
    {
        fprintf(stderr, "Failed to open config space file: %s\n", strerror(errno));
        return errno;
    }

    uint16_t command;
    fseek(fp, 0x04, SEEK_SET);
    fread(&command, sizeof(command), 1, fp);

    command |= (1 << 0x02);

    fseek(fp, 0x04, SEEK_SET);
    fwrite(&command, sizeof(command), 1, fp);

    fclose(fp);
    return 0;
}


/*
 * Open a file descriptor to device memory.
 */
static int pci_open_bar(const struct bdf* dev, int bar)
{
    char path[64];
    sprintf(path, "/sys/bus/pci/devices/%04x:%02x:%02x.%x/resource%d", 
            dev->domain, dev->bus, dev->device, dev->function, bar);

    int fd = open(path, O_RDWR);
    if (fd < 0)
    {
        fprintf(stderr, "Failed to open resource file: %s\n", strerror(errno));
    }

    return fd;
}

static int parse_bdf(const char* str, struct bdf* dev)
{
    const char* colon = strrchr(str, ':');
    const char* colon1 = strchr(str, ':');
    const char* dot = strchr(colon != NULL ? colon : str, '.');
    char* endptr;

    const char* function = "0";
    const char* slot = str;
    const char* bus = "0:";
    const char* domain = bus;

    if (colon != NULL)
    {
        bus = str;
        slot = colon + 1;

        if (colon != colon1)
        {
            domain = str;
            bus = colon1 + 1;
        }
    }

    if (dot != NULL)
    {
        function = dot + 1;
    }

    dev->domain = strtoul(domain, &endptr, 16);
    if (endptr == NULL || *endptr != ':' || dev->domain > 0xffff)
    {
        fprintf(stderr, "Invalid PCI domain number: '%s'\n", domain);
        return 1;
    }

    dev->bus = strtoul(bus, &endptr, 16);
    if (endptr == NULL || *endptr != ':' || dev->bus > 0xff)
    {
        fprintf(stderr, "Invalid PCI bus number: '%s'\n", bus);
        return 1;
    }

    dev->device = strtoul(slot, &endptr, 16);
    if (endptr == NULL || *endptr != '.' || dev->device > 0xff)
    {
        fprintf(stderr, "Invalid PCI device number: '%s'\n", slot);
        return 1;
    }

    dev->function = strtoul(function, &endptr, 0);
    if (endptr == NULL || *endptr != '\0')
    {
        fprintf(stderr, "Invalid PCI device function: '%s'\n", function);
        return 1;
    }

    return 0;
}

static int prepare_and_read(nvm_aq_ref ref, const struct disk_info* disk, const struct options* args)
{
    int status = 0;

    void* buffer_ptr = NULL;
    nvm_dma_t* buffer = NULL;
    void* queue_ptr = NULL;
    nvm_dma_t* sq_mem = NULL;
    nvm_dma_t* cq_mem = NULL;
    size_t n_prp_lists = disk->page_size / sizeof(nvm_cmd_t);
    struct queue_pair queues;

    const nvm_ctrl_t* ctrl = nvm_ctrl_from_aq_ref(ref);

/*
    status = posix_memalign(&buffer_ptr, disk->page_size, NVM_CTRL_ALIGN(ctrl, args->num_blocks * disk->block_size));
    if (status != 0)
    {
        fprintf(stderr, "Failed to allocate memory buffer: %s\n", strerror(status));
        goto leave;
    }

    status = posix_memalign(&queue_ptr, disk->page_size, disk->page_size * (n_prp_lists + 2));
    if (status != 0)
    {
        fprintf(stderr, "Failed to allocate queue memory: %s\n", strerror(status));
        goto leave;
    }

    status = nvm_dma_map_host(&sq_mem, ctrl, NVM_PTR_OFFSET(queue_ptr, disk->page_size, 1), disk->page_size * (n_prp_lists + 1));
    if (!nvm_ok(status))
    {
        fprintf(stderr, "Failed to map memory for controller: %s\n", nvm_strerror(status));
        goto leave;
    }

    status = nvm_dma_map_host(&cq_mem, ctrl, queue_ptr, disk->page_size);
    if (!nvm_ok(status))
    {
        fprintf(stderr, "Failed to map memory for controller: %s\n", nvm_strerror(status));
        goto leave;
    }

    status = nvm_dma_map_host(&buffer, ctrl, buffer_ptr, args->num_blocks * disk->block_size);
    if (!nvm_ok(status))
    {
        fprintf(stderr, "Failed to map memory for controller: %s\n", nvm_strerror(status));
        goto leave;
    }
*/

    status = test_dma_map(&sq_mem, ctrl, NULL, disk->page_size * (n_prp_lists + 1));
    if (!nvm_ok(status))
    {
        fprintf(stderr, "Failed to map memory for controller: %s\n", nvm_strerror(status));
        goto leave;
    }

    status = test_dma_map(&cq_mem, ctrl, NULL, disk->page_size);
    if (!nvm_ok(status))
    {
        fprintf(stderr, "Failed to map memory for controller: %s\n", nvm_strerror(status));
        goto leave;
    }

    status = test_dma_map(&buffer, ctrl, &buffer_ptr, args->num_blocks * disk->block_size);
    if (!nvm_ok(status))
    {
        fprintf(stderr, "Failed to map memory for controller: %s\n", nvm_strerror(status));
        goto leave;
    }

    memset(buffer->vaddr, 0, args->num_blocks * disk->block_size);

    status = create_queue_pair(ref, &queues, cq_mem, sq_mem);
    if (status != 0)
    {
        goto leave;
    }

    if (args->input != NULL)
    {
        status = write_blocks(disk, &queues, buffer, args);
        if (status != 0)
        {
            goto leave;
        }
    }

    status = read_and_dump(disk, &queues, buffer, args);

    status = nvm_admin_get_log_page(ref, args->namespace_id, mem, addr, 1, 0);

    void* err = mem;
    while (*(uint64_t*)err && err < mem + 4096) {
        fprintf(stderr, "Err log %x %llx SQ:%x ID:%x St:%x Loc:%x V:%x LBA:%llx C:%x\n", (int)status, *(uint64_t*)err, (uint32_t)*(uint16_t*)(err + 8), (uint32_t)*(uint16_t*)(err + 10), (uint32_t)*(uint16_t*)(err + 12), (uint32_t)*(uint16_t*)(err + 14), (uint32_t)*(uint8_t*)(err + 28), *(uint64_t*)(err + 16), *(uint32_t*)(err + 32));
        err += 64;
    }

leave:
    nvm_dma_unmap(buffer);
    nvm_dma_unmap(sq_mem);
    nvm_dma_unmap(cq_mem);
    //free(buffer_ptr);
    //free(queue_ptr);
    return status;
}

int main(int argc, char** argv)
{
    int status;
    int fd;

    struct disk_info disk;

    nvm_ctrl_t* ctrl = NULL;
    void* aq_ptr = NULL;
    nvm_dma_t* aq_mem = NULL;
    nvm_aq_ref aq_ref = NULL;

    struct options args;
    struct bdf device;

    // Parse arguments from command line
    parse_options(argc, argv, &args);


    if (parse_bdf(args.controller_path, &device) != 0) {
        fprintf(stderr, "Invalid device %s, expected xxxx:xx:xx.x\n", args.controller_path);
        exit(1);
    }

    // Enable device
    status = pci_enable_device(&device);
    if (status != 0)
    {
        fprintf(stderr, "Failed to enable device %04x:%02x:%02x.%x\n",
                device.domain, device.bus, device.device, device.function);
        exit(1);
    }

    // Enable device DMA
    status = pci_set_bus_master(&device);
    if (status != 0)
    {
        fprintf(stderr, "Failed to access device config space %04x:%02x:%02x.%x\n",
                device.domain, device.bus, device.device, device.function);
        exit(2);
    }

    // Memory-map device memory
    fd = pci_open_bar(&device, 0);
    if (fd < 0)
    {
        fprintf(stderr, "Failed to access device BAR memory\n");
        exit(3);
    }

    volatile void* ctrl_registers = mmap(NULL, NVM_CTRL_MEM_MINSIZE, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FILE, fd, 0);
    if (ctrl_registers == NULL || ctrl_registers == MAP_FAILED)
    {
        fprintf(stderr, "Failed to memory map BAR reasource file: %s\n", strerror(errno));
        close(fd);
        exit(3);
    }

    // Get controller reference
    status = nvm_raw_ctrl_init(&ctrl, ctrl_registers, NVM_CTRL_MEM_MINSIZE);
    if (status != 0)
    {
        munmap((void*) ctrl_registers, NVM_CTRL_MEM_MINSIZE);
        close(fd);
        fprintf(stderr, "Failed to get controller reference: %s\n", strerror(status));
        exit(4);
    }

/*
    // Get controller reference
    fd = open(args.controller_path, O_RDWR | O_NONBLOCK);
    if (fd < 0)
    {
        fprintf(stderr, "Failed to open file descriptor: %s\n", strerror(errno));
        exit(1);
    }

    status = nvm_ctrl_init(&ctrl, fd);
    if (!nvm_ok(status))
    {
        fprintf(stderr, "Failed to initialize controller reference: %s\n", nvm_strerror(status));
        goto leave;
    }
*/

/*
    // Create admin queue pair + page for identify commands
    status = posix_memalign(&aq_ptr, ctrl->page_size, ctrl->page_size * 3);
    if (status != 0)
    {
        fprintf(stderr, "Failed to allocate queue memory: %s\n", strerror(status));
        goto leave;
    }

    status = nvm_dma_map_host(&aq_mem, ctrl, aq_ptr, ctrl->page_size * 3);
    if (!nvm_ok(status))
    {
        fprintf(stderr, "Failed to map memory for controller: %s\n", nvm_strerror(status));
        goto leave;
    }
*/

    if (!setup_map()) {
        exit(2);
    }

    test_dma_map(&aq_mem, ctrl, NULL, ctrl->page_size * 3);

    // Reset controller and set admin queues
    status = nvm_aq_create(&aq_ref, ctrl, aq_mem);
    if (!nvm_ok(status))
    {
        fprintf(stderr, "Failed to reset controller: %s\n", nvm_strerror(status));
        goto leave;
    }

    // Identify controller and namespace
    status = get_disk_info(aq_ref, &disk, args.namespace_id, NVM_DMA_OFFSET(aq_mem, 2), aq_mem->ioaddrs[2], args.identify);
    if (status != 0)
    {
        goto leave;
    }

    status = prepare_and_read(aq_ref, &disk, &args);

leave:
    if (args.input != NULL)
    {
        fclose(args.input);
    }

    if (args.output != NULL)
    {
        fprintf(stderr, "Flushing output file...\n");
        fclose(args.output);
    }

    fprintf(stderr, "Done\n");

    nvm_aq_destroy(aq_ref);
    nvm_dma_unmap(aq_mem);
    //free(aq_ptr);
    nvm_ctrl_free(ctrl);
    close(fd);
    exit(status);
}
