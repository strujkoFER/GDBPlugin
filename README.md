GDB plugin for Ghidra


# About

This project was started as a Bachelors degree project and will continue it's development. I started it because of a need for tracking variables and easier dynamic analysis during CTF-s.


# Ghidra installation guide

To install Ghidra you can look at the guide at [Ghidra Github](https://github.com/nationalsecurityagency/ghidra).


# Plugin installation guide

The plugin itself is a .zip file located inside folder dist. You can just download that and then open up Ghidra and on the first window go to File -> Install Extensions.

<img width="1179" height="886" alt="image" src="https://github.com/user-attachments/assets/866499de-d1f8-4501-b9f9-042bf88338b5" />

After it opens a window you can press the plus button in the upper right corner

<img width="1051" height="149" alt="image" src="https://github.com/user-attachments/assets/426361f7-c4ef-47ac-9cea-23ecd4a27f2d" />

Then choose the .zip plugin file. Check the checkbox on the plugin if it isn't already checked and press "OK".

After that you will need to restart Ghidra and the next time you neter it will ask you to configure plugin.

<img width="613" height="206" alt="image" src="https://github.com/user-attachments/assets/50851ad0-3cef-4350-83f5-1243ece22951" />

Press "Yes" and after that check the checkbox on the plugin and press "OK".

<img width="1002" height="91" alt="image" src="https://github.com/user-attachments/assets/cb71b7a3-b533-4fb7-97bd-7f2faeadc0b9" />


If you don't see the windows right away, you can go to windows tab and find them there. You can drag them with mouse to wherever you want.


# Development

This is currently still my Bachelors degree project so any pull requests will be ignored for the time being. Thank you for understanding.

If you want to work on development you can clone the repository and send pull requests for changes. You wil need gradle to build the plugin. You can build the plugin in terminal in project folder using command: "gradle distributeExtension"



