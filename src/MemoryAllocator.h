// MemoryAllocator.h
#pragma once
#include <Windows.h>
#include <unordered_map>
#include <string>

// ǰ������
class ProcessManager;

class MemoryAllocator {
public:
    MemoryAllocator();
    ~MemoryAllocator();

    // ���ý��̹����������ڿ���̷��䣩
    void SetProcessManager(ProcessManager* pm) { m_processManager = pm; }

    // ��ָ����ַ���������ڴ�
    uintptr_t AllocateNear(uintptr_t nearAddress, size_t size, const std::string& name);

    // �ͷŷ�����ڴ�
    bool Deallocate(const std::string& name);

    // ��ȡ�ѷ����ڴ�ĵ�ַ
    uintptr_t GetAllocation(const std::string& name) const;

    // �������з���
    void ClearAll();

private:
    // ���Һ��ʵ��ڴ��ַ
    uintptr_t FindSuitableAddress(uintptr_t nearAddress, size_t size);

    struct Allocation {
        uintptr_t address;
        size_t size;
    };

    std::unordered_map<std::string, Allocation> m_allocations;
    ProcessManager* m_processManager;  // ��ѡ�����ڿ����
};