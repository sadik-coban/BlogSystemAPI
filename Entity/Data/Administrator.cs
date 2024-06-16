using Core.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Entity.Data;
public class Administrator : ApplicationUser
{
    public ICollection<Post> Posts { get; set; } = new HashSet<Post>();
    public ICollection<Author> Authors { get; set; } = new HashSet<Author>();
}
