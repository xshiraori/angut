#include <callbacks.hpp>
#include <utils.hpp>
#include <memory.hpp>

namespace callbacks {

    _OB_CALLBACK_ENTRY* get_object_callback_entry(callback_type callback_type)
    {
        _OBJECT_TYPE_2* object_type = nullptr;
        switch (callback_type)
        {
            case ProcessObject:
            {
                object_type = reinterpret_cast<_OBJECT_TYPE_2*>(*PsProcessType);
                break;
            }
            case ThreadObject:
            {
                object_type = reinterpret_cast<_OBJECT_TYPE_2*>(*PsThreadType);
                break;
            }
        }

        if (!object_type)
        {
            return nullptr;
        }

        return reinterpret_cast<_OB_CALLBACK_ENTRY*>(&object_type->CallbackList);
    }
}