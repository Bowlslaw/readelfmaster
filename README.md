# readelfmaster
A reimplementation of GNU readelf, using Ryan O'Neill's innovative library, [libelfmaster](https://github.com/elfmaster/libelfmaster).

This is a project so that I can both learn the libelfmaster library functionality better while contributing to the community. I have found this program useful in my own binary analysis during CTFs.

Begin by following the installation instructions for libelfmaster. You will need to include the libelfmaster header file as well as compile readelfmaster against the static libelfmaster.a library produced upon successful compilation of libelfmaster.

As we can see, readelf has no problem displaying the section headers of an ordinary binary:
![Alt text](https://github.com/Bowlslaw/readelfmaster/blob/master/readelfsections.png?raw=true "readelf is able to read sections from an untampered binary just fine")

However, malware authors will often attempt to make analysis of their software more difficult. One way is to strip the unneeded section headers:

![Alt text](https://github.com/Bowlslaw/readelfmaster/blob/master/readelfstrip.png?raw=true "readelf cannot reconstruct section headers from a stripped binary")

libelfmaster comes with the ability to reconstruct section headers, among other innovative functionality. Read more at the libelfmaster Github page.

![Alt text](https://github.com/Bowlslaw/readelfmaster/blob/master/readelfmastersections.pngraw=true "readelf cannot reconstruct section headers from a stripped binary")
