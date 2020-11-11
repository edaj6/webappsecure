using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace WebAppSecure.Controllers
{
    [ApiController]
    public class TestController : ControllerBase
    {

        [HttpGet("api/test")]
        public string Test()
        {
            return "Not secure text";
        }

        [HttpGet("api/sikker")]
        [Authorize]
        public string Sikker()
        {
            return "Secure text";
        }

    }
}
