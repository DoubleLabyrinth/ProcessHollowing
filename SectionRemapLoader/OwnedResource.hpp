#pragma once
#include <type_traits>

template<typename __ResourceTraits>
class OwnedResource {
private:
    using HandleType = typename __ResourceTraits::HandleType;

    HandleType _Handle;
public:

    OwnedResource() noexcept :
        _Handle(__ResourceTraits::InvalidValue) {}

    explicit OwnedResource(HandleType Handle) noexcept :
        _Handle(Handle) {}

    OwnedResource(const OwnedResource<__ResourceTraits>& Other) = delete;

    OwnedResource(OwnedResource<__ResourceTraits>&& Other) noexcept :
        _Handle(Other._Handle) 
    {
        Other._Handle = __ResourceTraits::InvalidValue;
    }

    OwnedResource<__ResourceTraits>& operator=(const OwnedResource<__ResourceTraits>& Other) = delete;

    OwnedResource<__ResourceTraits>& operator=(OwnedResource<__ResourceTraits>&& Other) noexcept {
        _Handle = Other._Handle;
        Other._Handle = __ResourceTraits::InvalidValue;
        return *this;
    }

    operator HandleType() const noexcept {
        return _Handle;
    }

    template<typename __Dummy = typename std::enable_if<std::is_pointer<HandleType>::value>::type>
    HandleType operator->() noexcept {
        return _Handle;
    }

    template<typename __Dummy = typename std::enable_if<std::is_pointer<HandleType>::value>::type>
    const HandleType operator->() const noexcept {
        return _Handle;
    }

    template<typename __AsType, typename __Dummy = typename std::enable_if<std::is_pointer<HandleType>::value>::type>
    __AsType As() const noexcept {
        return reinterpret_cast<__AsType>(_Handle);
    }

    bool IsValid() const noexcept {
        return _Handle != __ResourceTraits::InvalidValue;
    }

    HandleType Get() const noexcept {
        return _Handle;
    }

    template<typename __ReturnType = HandleType*>
    __ReturnType GetAddress() noexcept {
        return &_Handle;
    }

    void TakeOver(HandleType Handle) {
        if (_Handle == __ResourceTraits::InvalidValue) {
            _Handle = Handle;
        } else {
            __ResourceTraits::Releasor(_Handle);
            _Handle = Handle;
        }
    }

    void Abandon() noexcept {
        _Handle = __ResourceTraits::InvalidValue;
    }

    void Release() {
        if (_Handle != __ResourceTraits::InvalidValue) {
            __ResourceTraits::Releasor(_Handle);
            _Handle = __ResourceTraits::InvalidValue;
        }
    }

    ~OwnedResource() {
        if (_Handle != __ResourceTraits::InvalidValue) {
            __ResourceTraits::Releasor(_Handle);
            _Handle = __ResourceTraits::InvalidValue;
        }
    }
};

template<typename __ClassType>
struct CppObjectTraits {
    using HandleType = __ClassType*;
    static inline const HandleType InvalidValue = nullptr;
    static void Releasor(HandleType pObject) {
        delete pObject;
    }
};

template<typename __ClassType>
struct CppDynamicArrayTraits {
    using HandleType = __ClassType*;
    static inline const HandleType InvalidValue = nullptr;
    static void Releasor(HandleType pObject) {
        delete[] pObject;
    }
};
