int putdata(const unsigned char *start, const size_t len, 
                  unsigned char **cur, const void *data, const size_t datalen) {
     unsigned char *p;
     
     p=*cur;
     if (datalen > len - (p - start))
          return 1;
     memcpy(p, data, datalen);
     p+=datalen;
     *cur=p;
     return 0;
}

int putint(const unsigned char *start, const size_t len, 
                     unsigned char **cur, const unsigned int data) {
     unsigned int sdata = htonl(data);
     return putdata(start, len, cur, &sdata, 4);
}


int getdata(const unsigned char *start, const size_t len, 
                  unsigned char **cur, void *data, const size_t datalen) {
     unsigned char *p;
     
     p=*cur;
     if (datalen > len - (p - start))
          return 1;
     memcpy(data, p, datalen);
     p+=datalen;
     *cur=p;
     return 0;
}

int getint(const unsigned char *start, const size_t len, 
                     unsigned char **cur, unsigned int *data) {
     unsigned int sdata;
     
     if (getdata(start, len, cur, &sdata, 4))
          return 1;
     *data = ntohl(sdata);
     return 0;
}
