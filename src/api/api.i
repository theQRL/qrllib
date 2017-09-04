%module pyqrlfast
%{
    #include "api.h"
%}

%include "carrays.i"
%include "cdata.i"

%array_class(unsigned char, ucharArray)

%include "api.h"
