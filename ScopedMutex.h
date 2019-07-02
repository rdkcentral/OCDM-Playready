#pragma once

#include <core/Sync.h>

class ScopedMutex
{
public:
    explicit ScopedMutex(WPEFramework::Core::CriticalSection& lock) : mLock(lock), mLocked(false)
    {
        relock();
    }

    /** Release the lock. */
    ~ScopedMutex()
    {
        unlock();
    }

    void unlock()
    {
        if (mLocked) {
            mLocked = false;
            mLock.Unlock();
        }
    }

    void relock()
    {
        if (!mLocked) {
            mLocked = true;
            mLock.Lock();
        }
    }

    WPEFramework::Core::CriticalSection &mutex() { return mLock; }
    const WPEFramework::Core::CriticalSection &mutex() const { return mLock; }
private:
    WPEFramework::Core::CriticalSection& mLock; //!< The acquired lock.
    bool mLocked;
};
