# pam_motd
Porting Debian/Ubuntu flavor of pam_motd (a part of Linux-PAM) to OpenPAM used by FreeBSD, macOS, and some Linux distros.

# Build&Install

```shell
$ mkdir build && cd build
$ cmake .. && make 
$ sudo make install # Root priviledge required.
```

`run-parts`(in `debianutils`) is required to make the module able to run the scripts in `/etc/update-motd.d`.

Some CMake Options:

| Options | Default value | Comments |
|---------|---------------|----------|
| PAM_MOTD_REGEN_MAN | OFF  | Regenerate pam_motd.8.xml        |
| PAM_MOTD_INSTALL_MAN | ON | Install Manuals |

----------------
# DISCLAMER

THIS SOFTWARE IS PROVIDED 'AS IS' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.

IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.