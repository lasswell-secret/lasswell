int r = 0, b = 0;              // 等待的红客数和黑客数
semaphore mutex = 1;
semaphore redQ = 0, blackQ = 0;
semaphore arrive = 0;
semaphore boarded = 0;

Red() {
    P(mutex);
    r++;
    V(mutex);

    V(arrive);
    P(redQ);

    上船;
    V(boarded);
}

Black() {
    P(mutex);
    b++;
    V(mutex);

    V(arrive);
    P(blackQ);

    上船;
    V(boarded);
}

Boat() {
    while (true) {
        P(mutex);

        while (r < 4 && b < 4 && !(r >= 2 && b >= 2)) {
            V(mutex);
            P(arrive);
            P(mutex);
        }

        if (r >= 2 && b >= 2) {
            r -= 2;
            b -= 2;
            V(redQ);
            V(redQ);
            V(blackQ);
            V(blackQ);
        }
        else if (r >= 4) {
            r -= 4;
            V(redQ);
            V(redQ);
            V(redQ);
            V(redQ);
        }
        else {
            b -= 4;
            V(blackQ);
            V(blackQ);
            V(blackQ);
            V(blackQ);
        }

        V(mutex);

        P(boarded);
        P(boarded);
        P(boarded);
        P(boarded);

        开船过河;
        空船返回;
    }
}