#pragma once

#include <WPEFramework/core/Sync.h>

// TODO: does something like this exist in WPEFramework?
//       If not, maybe copy? If yes, replace this one with the original one.
// TODO: This is just a simpler version of Netflix's ScopedMutex (worry about license?)
// TODO: rename
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
